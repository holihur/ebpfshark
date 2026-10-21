// Package stream reassembles TCP payloads per direction so the UI can offer a
// Wireshark-style "Follow TCP Stream" view.
package stream

import (
	"strconv"
	"sync"
	"time"

	"ebpfshark/internal/packet"
)

// DefaultBudget is the memory budget for reassembled payloads.
const DefaultBudget int64 = 64 << 20

const (
	maxFlows = 4096
	maxGaps  = 1024
)

// Endpoint identifies one side of a TCP conversation.
type Endpoint struct {
	IP   string `json:"ip"`
	Port uint16 `json:"port"`
}

// Direction is one half of a reassembled conversation.
type Direction struct {
	From      Endpoint `json:"from"`
	To        Endpoint `json:"to"`
	Bytes     int      `json:"bytes"`
	Truncated bool     `json:"truncated"`
	Gaps      int      `json:"gaps"`
	Data      []byte   `json:"-"`
}

// Snapshot is a point-in-time copy of a reassembled conversation.
type Snapshot struct {
	Key   string    `json:"key"`
	A     Endpoint  `json:"a"`
	B     Endpoint  `json:"b"`
	AtoB  Direction `json:"aToB"`
	BtoA  Direction `json:"bToA"`
	First time.Time `json:"first"`
	Last  time.Time `json:"last"`
}

// Stats reports reassembly memory usage.
type Stats struct {
	Flows       int    `json:"flows"`
	Bytes       int64  `json:"bytes"`
	Evicted     uint64 `json:"evicted"`
	BudgetBytes int64  `json:"budgetBytes"`
}

type conversation struct {
	key      string
	a, b     Endpoint
	a2b, b2a *assembler
	first    time.Time
	last     time.Time
}

// Manager tracks TCP conversations and reassembles their payloads.
type Manager struct {
	mu         sync.Mutex
	convs      map[string]*conversation
	totalBytes int64
	budget     int64
	dirLimit   int
	evicted    uint64
}

// NewManager creates a manager with a global payload budget in bytes.
func NewManager(budget int64) *Manager {
	if budget <= 0 {
		budget = DefaultBudget
	}
	if budget < 4<<20 {
		budget = 4 << 20
	}
	dirLimit := int(budget / 16)
	if dirLimit < 256<<10 {
		dirLimit = 256 << 10
	}
	if dirLimit > 2<<20 {
		dirLimit = 2 << 20
	}
	return &Manager{
		convs:    make(map[string]*conversation),
		budget:   budget,
		dirLimit: dirLimit,
	}
}

// Add feeds a TCP packet into the reassembly buffers. Packets without payload
// are ignored except for SYNs, which establish the initial sequence base.
func (m *Manager) Add(p *packet.Packet) {
	meta := &p.Meta
	if !meta.HasLayer("tcp") || !meta.SrcIP.IsValid() || !meta.DstIP.IsValid() {
		return
	}
	hasSyn := meta.TCPFlags&0x02 != 0
	payload := meta.TCPPayload
	if len(payload) == 0 && !hasSyn {
		return
	}

	key, a, b, reverse, ok := canonical(meta.SrcIP.String(), meta.SrcPort, meta.DstIP.String(), meta.DstPort)
	if !ok {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	c, ok := m.convs[key]
	if !ok {
		c = &conversation{
			key: key,
			a:   a,
			b:   b,
			a2b: newAssembler(m.dirLimit),
			b2a: newAssembler(m.dirLimit),
		}
		m.convs[key] = c
	}
	if c.first.IsZero() || (!p.Time.IsZero() && p.Time.Before(c.first)) {
		c.first = p.Time
	}
	if p.Time.After(c.last) {
		c.last = p.Time
	}

	dir := c.a2b
	if reverse {
		dir = c.b2a
	}
	dataSeq := meta.TCPSeq
	if hasSyn {
		dataSeq++ // SYN consumes one sequence number
		dir.start(dataSeq)
	}
	if len(payload) > 0 {
		before := dir.size()
		dir.add(dataSeq, payload)
		m.totalBytes += int64(dir.size() - before)
	}
	m.enforceLimitsLocked()
}

// Get returns a snapshot for a conversation key.
func (m *Manager) Get(key string) (*Snapshot, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.convs[key]
	if !ok {
		return nil, false
	}
	snap := c.snapshot()
	return &snap, true
}

// ForPacket returns the conversation that contains p.
func (m *Manager) ForPacket(p *packet.Packet) (*Snapshot, bool) {
	key, _, _, _, ok := canonical(p.Meta.SrcIP.String(), p.Meta.SrcPort, p.Meta.DstIP.String(), p.Meta.DstPort)
	if !ok {
		return nil, false
	}
	return m.Get(key)
}

// Reset drops all reassembled data.
func (m *Manager) Reset() {
	m.mu.Lock()
	m.convs = make(map[string]*conversation)
	m.totalBytes = 0
	m.evicted = 0
	m.mu.Unlock()
}

// Stats returns a snapshot of manager statistics.
func (m *Manager) Stats() Stats {
	m.mu.Lock()
	defer m.mu.Unlock()
	return Stats{
		Flows:       len(m.convs),
		Bytes:       m.totalBytes,
		Evicted:     m.evicted,
		BudgetBytes: m.budget,
	}
}

func (m *Manager) enforceLimitsLocked() {
	for (len(m.convs) > maxFlows || m.totalBytes > m.budget) && len(m.convs) > 0 {
		var oldestKey string
		var oldest time.Time
		for key, c := range m.convs {
			if oldestKey == "" || c.last.Before(oldest) {
				oldestKey = key
				oldest = c.last
			}
		}
		if oldestKey == "" {
			return
		}
		c := m.convs[oldestKey]
		m.totalBytes -= int64(c.a2b.size() + c.b2a.size())
		delete(m.convs, oldestKey)
		m.evicted++
	}
}

func (c *conversation) snapshot() Snapshot {
	return Snapshot{
		Key:   c.key,
		A:     c.a,
		B:     c.b,
		AtoB:  c.a2b.snapshot(c.a, c.b),
		BtoA:  c.b2a.snapshot(c.b, c.a),
		First: c.first,
		Last:  c.last,
	}
}

// canonical sorts the endpoints so both directions map to one key.
func canonical(srcIP string, srcPort uint16, dstIP string, dstPort uint16) (key string, a, b Endpoint, reverse bool, ok bool) {
	if srcIP == "" || dstIP == "" {
		return "", Endpoint{}, Endpoint{}, false, false
	}
	a = Endpoint{IP: srcIP, Port: srcPort}
	b = Endpoint{IP: dstIP, Port: dstPort}
	if a.IP > b.IP || (a.IP == b.IP && a.Port > b.Port) {
		a, b = b, a
		reverse = true
	}
	key = "tcp|" + a.IP + "|" + strconv.Itoa(int(a.Port)) + "|" + b.IP + "|" + strconv.Itoa(int(b.Port))
	return key, a, b, reverse, true
}

// assembler rebuilds one direction of a byte stream.
type assembler struct {
	started   bool
	base      uint32
	buf       []byte
	gaps      map[int64][]byte
	limit     int
	truncated bool
}

func newAssembler(limit int) *assembler {
	if limit <= 0 {
		limit = 1 << 20
	}
	return &assembler{limit: limit, gaps: make(map[int64][]byte)}
}

func (a *assembler) start(base uint32) {
	if a.started {
		return
	}
	a.started = true
	a.base = base
}

func (a *assembler) size() int { return len(a.buf) }

func (a *assembler) add(seq uint32, data []byte) {
	if len(data) == 0 {
		return
	}
	if !a.started {
		a.started = true
		a.base = seq
	}
	if a.truncated && len(a.buf) >= a.limit {
		return
	}

	off := int64(int32(seq - a.base))
	if off < 0 {
		skip := -off
		if skip >= int64(len(data)) {
			return
		}
		data = data[skip:]
		off = 0
	}

	cur := int64(len(a.buf))
	end := off + int64(len(data))
	if off <= cur {
		if end <= cur {
			return // pure retransmission / already covered
		}
		data = data[cur-off:]
		off = cur
	}

	if off == cur {
		a.appendBytes(data)
		for {
			next := int64(len(a.buf))
			gap, ok := a.gaps[next]
			if !ok {
				break
			}
			delete(a.gaps, next)
			a.appendBytes(gap)
		}
		return
	}

	// Out-of-order data: keep it until the hole is filled.
	if len(a.gaps) >= maxGaps {
		a.truncated = true
		return
	}
	if old, ok := a.gaps[off]; !ok || len(old) < len(data) {
		cp := make([]byte, len(data))
		copy(cp, data)
		a.gaps[off] = cp
	}
}

func (a *assembler) appendBytes(data []byte) {
	if len(data) == 0 {
		return
	}
	remain := a.limit - len(a.buf)
	if remain <= 0 {
		a.truncated = true
		return
	}
	if len(data) > remain {
		data = data[:remain]
		a.truncated = true
	}
	a.buf = append(a.buf, data...)
}

func (a *assembler) snapshot(from, to Endpoint) Direction {
	data := make([]byte, len(a.buf))
	copy(data, a.buf)
	return Direction{
		From:      from,
		To:        to,
		Bytes:     len(data),
		Truncated: a.truncated,
		Gaps:      len(a.gaps),
		Data:      data,
	}
}
