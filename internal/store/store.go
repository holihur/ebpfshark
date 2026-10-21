// Package store keeps an in-memory ring of captured packets, aggregate
// statistics, conversations, and live subscribers.
package store

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"ebpfshark/internal/decode"
	"ebpfshark/internal/filter"
	"ebpfshark/internal/packet"
	"ebpfshark/internal/stream"
)

// Subscriber receives packets that match its filter.
type Subscriber struct {
	ID        int64
	C         chan *packet.Packet
	Filter    filter.Filter
	FilterKey string // canonical expression, used to evaluate identical filters once

	dropped atomic.Uint64
}

// Dropped returns the number of packets dropped for this subscriber because it
// could not keep up.
func (s *Subscriber) Dropped() uint64 { return s.dropped.Load() }

// Flow is a bidirectional conversation.
type Flow struct {
	Key      string    `json:"key"`
	Protocol string    `json:"protocol"`
	App      string    `json:"app,omitempty"`
	Src      string    `json:"src"`
	Dst      string    `json:"dst"`
	SrcPort  uint16    `json:"srcPort,omitempty"`
	DstPort  uint16    `json:"dstPort,omitempty"`
	Packets  uint64    `json:"packets"`
	Bytes    uint64    `json:"bytes"`
	PacketsA uint64    `json:"packetsA"`
	PacketsB uint64    `json:"packetsB"`
	BytesA   uint64    `json:"bytesA"`
	BytesB   uint64    `json:"bytesB"`
	First    time.Time `json:"first"`
	Last     time.Time `json:"last"`
	State    string    `json:"state,omitempty"`
	TCPFlags uint8     `json:"tcpFlags"`
}

type rateBucket struct {
	packets uint64
	bytes   uint64
}

type Store struct {
	mu   sync.RWMutex
	buf  []*packet.Packet
	head int
	n    int

	nextID uint64

	maxPackets int
	capacity   int

	total   uint64
	bytes   uint64
	evicted uint64
	dropped atomic.Uint64

	protoCounts map[string]uint64
	flows       map[string]*Flow
	maxFlows    int

	buckets    []rateBucket
	bucketSecs int64

	subs    map[int64]*Subscriber
	nextSub int64

	streams *stream.Manager

	started time.Time
}

// New creates a store retaining at most maxPackets packets.
func New(maxPackets int) *Store {
	if maxPackets < 1000 {
		maxPackets = 1000
	}
	return &Store{
		buf:         make([]*packet.Packet, maxPackets),
		maxPackets:  maxPackets,
		protoCounts: make(map[string]uint64),
		flows:       make(map[string]*Flow),
		maxFlows:    20000,
		buckets:     make([]rateBucket, 60),
		bucketSecs:  time.Now().Unix(),
		subs:        make(map[int64]*Subscriber),
		streams:     stream.NewManager(stream.DefaultBudget),
		started:     time.Now(),
	}
}

// Capacity is the maximum number of retained packets.
func (s *Store) Capacity() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.maxPackets
}

// Add dissects and stores a packet, then fans it out to subscribers.
func (s *Store) Add(p *packet.Packet) {
	if p.Summary.Protocol == "" {
		res := decode.Decode(p.Data, p.LinkType, int(p.WireLen))
		p.Summary = res.Summary
		p.Meta = res.Meta
		p.LinkType = res.Meta.LinkType
		decode.ReleaseFields(res.Fields)
	}
	if p.Time.IsZero() {
		p.Time = time.Now()
	}
	if s.streams != nil {
		s.streams.Add(p)
	}

	s.mu.Lock()
	id := s.nextID
	s.nextID++
	p.ID = id + 1
	p.Meta.ID = p.ID
	p.Meta.Number = p.ID

	if s.n == s.maxPackets {
		// overwrite oldest
		old := s.buf[s.head]
		if old != nil {
			s.evicted++
		}
		s.buf[s.head] = p
		s.head = (s.head + 1) % s.maxPackets
	} else {
		s.buf[(s.head+s.n)%s.maxPackets] = p
		s.n++
	}

	s.total++
	s.bytes += uint64(p.WireLen)
	proto := p.Summary.Protocol
	if proto == "" {
		proto = "Frame"
	}
	s.protoCounts[proto]++
	s.updateRates(p)
	s.updateFlow(p)

	var recipients []*Subscriber
	matches := make(map[string]bool)
	for _, sub := range s.subs {
		if sub.Filter == nil {
			recipients = append(recipients, sub)
			continue
		}
		ok := false
		if key := sub.FilterKey; key != "" {
			if v, hit := matches[key]; hit {
				ok = v
			} else {
				ok = sub.Filter.Match(&p.Meta)
				matches[key] = ok
			}
		} else {
			ok = sub.Filter.Match(&p.Meta)
		}
		if ok {
			recipients = append(recipients, sub)
		}
	}
	s.mu.Unlock()

	for _, sub := range recipients {
		select {
		case sub.C <- p:
		default:
			sub.dropped.Add(1)
			s.dropped.Add(1)
		}
	}
}

func (s *Store) updateRates(p *packet.Packet) {
	sec := p.Time.Unix()
	if sec > s.bucketSecs {
		// clear all buckets between the last update and now
		gap := sec - s.bucketSecs
		if gap >= int64(len(s.buckets)) {
			for i := range s.buckets {
				s.buckets[i] = rateBucket{}
			}
		} else {
			for i := int64(1); i <= gap; i++ {
				s.buckets[(s.bucketSecs+i)%int64(len(s.buckets))] = rateBucket{}
			}
		}
		s.bucketSecs = sec
	}
	// Ignore packets older than the rate window (e.g. imported pcap files):
	// their bucket index would collide with a slot in the current window.
	if sec <= s.bucketSecs-int64(len(s.buckets)) {
		return
	}
	idx := sec % int64(len(s.buckets))
	s.buckets[idx].packets++
	s.buckets[idx].bytes += uint64(p.WireLen)
}

func (s *Store) updateFlow(p *packet.Packet) {
	m := &p.Meta
	if m.SrcIP.IsValid() && m.DstIP.IsValid() {
		// normalise endpoint order
		aIP, bIP := m.SrcIP, m.DstIP
		aPort, bPort := m.SrcPort, m.DstPort
		reverse := false
		if aIP.String() > bIP.String() || (aIP == bIP && aPort > bPort) {
			aIP, bIP = bIP, aIP
			aPort, bPort = bPort, aPort
			reverse = true
		}
		proto := "IP"
		if m.HasLayer("tcp") {
			proto = "TCP"
		} else if m.HasLayer("udp") {
			proto = "UDP"
		} else if m.HasLayer("icmp") || m.HasLayer("icmpv6") {
			proto = "ICMP"
		} else if m.HasLayer("ipv6") {
			proto = "IPv6"
		}
		key := aIP.String() + "|" + bIP.String() + "|" + proto + "|" + itoa(aPort) + "|" + itoa(bPort)
		f, ok := s.flows[key]
		if !ok {
			if len(s.flows) >= s.maxFlows+s.maxFlows/16 {
				s.evictFlow()
			}
			f = &Flow{
				Key:      key,
				Protocol: proto,
				Src:      aIP.String(),
				Dst:      bIP.String(),
				SrcPort:  aPort,
				DstPort:  bPort,
				First:    p.Time,
			}
			s.flows[key] = f
		}
		f.Last = p.Time
		f.Packets++
		f.Bytes += uint64(p.WireLen)
		if reverse {
			f.PacketsB++
			f.BytesB += uint64(p.WireLen)
		} else {
			f.PacketsA++
			f.BytesA += uint64(p.WireLen)
		}
		if m.HasLayer("tcp") {
			f.TCPFlags |= m.TCPFlags
			f.State = tcpState(f.TCPFlags)
		} else if f.State == "" {
			f.State = "—"
		}
		if m.App != "" && f.App == "" {
			f.App = appName(m.App)
		}
	}
}

func itoa(v uint16) string {
	if v == 0 {
		return "0"
	}
	var b [6]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

func appName(s string) string {
	switch s {
	case "http":
		return "HTTP"
	case "dns":
		return "DNS"
	case "tls":
		return "TLS"
	case "dhcp":
		return "DHCP"
	}
	return s
}

func tcpState(flags uint8) string {
	switch {
	case flags&0x04 != 0:
		return "RESET"
	case flags&0x01 != 0:
		return "CLOSED"
	case flags&0x02 != 0 && flags&0x10 != 0:
		return "SYN-ACK"
	case flags&0x02 != 0:
		return "SYN"
	case flags&0x10 != 0:
		return "ESTABLISHED"
	}
	return "—"
}

func (s *Store) evictFlow() {
	type item struct {
		key  string
		last time.Time
	}
	items := make([]item, 0, len(s.flows))
	for k, f := range s.flows {
		items = append(items, item{k, f.Last})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].last.Before(items[j].last) })
	target := s.maxFlows / 8
	if target < 64 {
		target = 64
	}
	for i := 0; i < len(items) && i < target; i++ {
		if len(s.flows) <= s.maxFlows*95/100 {
			break
		}
		delete(s.flows, items[i].key)
	}
}

// Snapshot returns up to limit matching packets, oldest first.
func (s *Store) Snapshot(f filter.Filter, limit int) []*packet.Packet {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 || limit > s.n {
		limit = s.n
	}
	out := make([]*packet.Packet, 0, limit)
	for i := s.n - 1; i >= 0 && len(out) < limit; i-- {
		p := s.buf[(s.head+i)%s.maxPackets]
		if p == nil {
			continue
		}
		if f == nil || f.Match(&p.Meta) {
			out = append(out, p)
		}
	}
	// reverse
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// All returns all retained packets, oldest first. Intended for pcap export.
func (s *Store) All(f filter.Filter) []*packet.Packet {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*packet.Packet, 0, s.n)
	for i := 0; i < s.n; i++ {
		p := s.buf[(s.head+i)%s.maxPackets]
		if p == nil {
			continue
		}
		if f == nil || f.Match(&p.Meta) {
			out = append(out, p)
		}
	}
	return out
}

// Get returns the packet with the given id.
func (s *Store) Get(id uint64) (*packet.Packet, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.n == 0 {
		return nil, false
	}
	oldest := s.buf[s.head].ID
	if id < oldest || id >= oldest+uint64(s.n) {
		return nil, false
	}
	p := s.buf[(s.head+int(id-oldest))%s.maxPackets]
	if p == nil || p.ID != id {
		return nil, false
	}
	return p, true
}

// SetStreamBudget configures the TCP reassembly memory budget. It is meant to
// be called once at startup and resets any buffered streams.
func (s *Store) SetStreamBudget(bytes int64) {
	s.mu.Lock()
	s.streams = stream.NewManager(bytes)
	s.mu.Unlock()
}

// StreamForPacket returns the reassembled TCP stream that contains p.
func (s *Store) StreamForPacket(p *packet.Packet) (*stream.Snapshot, bool) {
	if s.streams == nil {
		return nil, false
	}
	return s.streams.ForPacket(p)
}

// StreamStats returns TCP reassembly statistics.
func (s *Store) StreamStats() stream.Stats {
	if s.streams == nil {
		return stream.Stats{}
	}
	return s.streams.Stats()
}

// Clear removes all retained packets, statistics and conversations.
func (s *Store) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.streams != nil {
		s.streams.Reset()
	}
	for i := range s.buf {
		s.buf[i] = nil
	}
	s.head, s.n = 0, 0
	s.nextID = 0
	s.total, s.bytes, s.evicted = 0, 0, 0
	s.dropped.Store(0)
	s.protoCounts = make(map[string]uint64)
	s.flows = make(map[string]*Flow)
	for i := range s.buckets {
		s.buckets[i] = rateBucket{}
	}
	s.bucketSecs = time.Now().Unix()
}

// Stats is a point in time snapshot of capture statistics.
type Stats struct {
	Stored      int               `json:"stored"`
	Capacity    int               `json:"capacity"`
	Total       uint64            `json:"total"`
	Bytes       uint64            `json:"bytes"`
	Evicted     uint64            `json:"evicted"`
	Dropped     uint64            `json:"dropped"`
	Protocols   map[string]uint64 `json:"protocols"`
	Rate        []RatePoint       `json:"rate"`
	Streams     stream.Stats      `json:"streams"`
	FirstPacket time.Time         `json:"firstPacket,omitempty"`
	LastPacket  time.Time         `json:"lastPacket,omitempty"`
}

// RatePoint is one second of traffic.
type RatePoint struct {
	Time    int64  `json:"time"`
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

// Stats returns a consistent snapshot of store statistics.
func (s *Store) Stats() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	protos := make(map[string]uint64, len(s.protoCounts))
	for k, v := range s.protoCounts {
		protos[k] = v
	}
	now := time.Now().Unix()
	rates := make([]RatePoint, 0, len(s.buckets))
	start := now - int64(len(s.buckets)) + 1
	for sec := start; sec <= now; sec++ {
		// Buckets after the last observed packet are stale and must read as 0.
		if sec > s.bucketSecs {
			rates = append(rates, RatePoint{Time: sec})
			continue
		}
		b := s.buckets[(sec%int64(len(s.buckets))+int64(len(s.buckets)))%int64(len(s.buckets))]
		rates = append(rates, RatePoint{Time: sec, Packets: b.packets, Bytes: b.bytes})
	}
	st := Stats{
		Stored:    s.n,
		Capacity:  s.maxPackets,
		Total:     s.total,
		Bytes:     s.bytes,
		Evicted:   s.evicted,
		Dropped:   s.dropped.Load(),
		Protocols: protos,
		Rate:      rates,
		Streams:   s.streams.Stats(),
	}
	if s.n > 0 {
		st.FirstPacket = s.buf[s.head].Time
		st.LastPacket = s.buf[(s.head+s.n-1)%s.maxPackets].Time
	}
	return st
}

// Flows returns conversations sorted by bytes, descending.
func (s *Store) Flows(limit int) []*Flow {
	s.mu.RLock()
	out := make([]*Flow, 0, len(s.flows))
	for _, f := range s.flows {
		cp := *f
		out = append(out, &cp)
	}
	s.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].Bytes == out[j].Bytes {
			return out[i].Packets > out[j].Packets
		}
		return out[i].Bytes > out[j].Bytes
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// Subscribe registers a live subscriber. The caller must Unsubscribe.
func (s *Store) Subscribe(f filter.Filter, buf int) *Subscriber {
	return s.SubscribeKey(f, "", buf)
}

// SubscribeKey is Subscribe with a stable filter expression key. Subscribers
// sharing a key have their filter evaluated once per packet.
func (s *Store) SubscribeKey(f filter.Filter, key string, buf int) *Subscriber {
	if buf <= 0 {
		buf = 2048
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextSub++
	sub := &Subscriber{
		ID:        s.nextSub,
		C:         make(chan *packet.Packet, buf),
		Filter:    f,
		FilterKey: key,
	}
	if f == nil {
		sub.Filter = filterAll{}
	}
	s.subs[sub.ID] = sub
	return sub
}

// Unsubscribe removes a subscriber. Its channel is intentionally not closed:
// Add may still hold a reference collected before removal, and the subscriber
// stops reading once its request context is done.
func (s *Store) Unsubscribe(sub *Subscriber) {
	s.mu.Lock()
	delete(s.subs, sub.ID)
	s.mu.Unlock()
}

// SubscriberCount returns the number of live subscribers.
func (s *Store) SubscriberCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.subs)
}

type filterAll struct{}

func (filterAll) Match(*packet.Meta) bool { return true }
