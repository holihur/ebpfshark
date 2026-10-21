package capture

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"ebpfshark/internal/packet"
	"ebpfshark/internal/store"
)

const eventHeaderLen = 24 // sizeof(struct pkt_event)

// Options configures a capture session.
type Options struct {
	Interfaces []string `json:"interfaces"`
	Snaplen    uint32   `json:"snaplen"`
	SampleRate uint32   `json:"sampleRate"`
	RingSize   uint32   `json:"ringSize"`
	// ExcludePort drops TCP/UDP packets whose source or destination port
	// matches it (the analyzer's own HTTP API). 0 disables the filter.
	ExcludePort uint32 `json:"excludePort"`
}

// Status describes the current capture session.
type Status struct {
	Running        bool     `json:"running"`
	Interfaces     []string `json:"interfaces"`
	Snaplen        uint32   `json:"snaplen"`
	SampleRate     uint32   `json:"sampleRate"`
	RingSize       uint32   `json:"ringSize"`
	KernelPackets  uint64   `json:"kernelPackets"`
	KernelBytes    uint64   `json:"kernelBytes"`
	KernelSkipped  uint64   `json:"kernelSkipped"`
	KernelFiltered uint64   `json:"kernelFiltered"`
	ExcludePort    uint32   `json:"excludePort"`
	UptimeSeconds  float64  `json:"uptimeSeconds"`
	AttachErrors   []string `json:"attachErrors,omitempty"`
	LastError      string   `json:"lastError,omitempty"`
}

// Manager owns the eBPF objects and TCX attachments for one capture session.
type Manager struct {
	store *store.Store
	log   *slog.Logger

	mu      sync.Mutex
	objs    *captureObjects
	reader  *ringbuf.Reader
	links   []link.Link
	opts    Options
	running bool
	start   time.Time
	wallOff int64 // wall clock offset for bpf_ktime_get_ns timestamps
	wg      sync.WaitGroup

	attachErrors []string
	lastError    string

	lastKernelPackets  uint64
	lastKernelBytes    uint64
	lastKernelSkipped  uint64
	lastKernelFiltered uint64

	// ifaceNames maps ifindex to name for the current session. It is written
	// before the reader goroutine starts and never mutated while it runs.
	ifaceNames map[uint32]string
}

// NewManager creates a capture manager feeding packets into st.
func NewManager(st *store.Store, log *slog.Logger) *Manager {
	return &Manager{store: st, log: log}
}

// Start tears down any running session and starts a new one.
func (m *Manager) Start(opts Options) error {
	m.Stop()

	if len(opts.Interfaces) == 0 {
		return errors.New("no interfaces selected")
	}
	if opts.Snaplen == 0 {
		opts.Snaplen = 256
	}
	if opts.Snaplen > 2048 {
		opts.Snaplen = 2048
	}
	if opts.SampleRate == 0 {
		opts.SampleRate = 1
	}
	if opts.RingSize == 0 {
		opts.RingSize = 32 << 20
	}
	if opts.RingSize < 1<<16 {
		opts.RingSize = 1 << 16
	}
	if opts.RingSize > 1<<28 {
		opts.RingSize = 1 << 28
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		m.log.Warn("failed to raise memlock limit", "err", err)
	}

	spec, err := loadCapture()
	if err != nil {
		return fmt.Errorf("load eBPF spec: %w", err)
	}
	if ms, ok := spec.Maps["events"]; ok {
		ms.MaxEntries = opts.RingSize
	}

	var objs captureObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return fmt.Errorf("load eBPF objects: %w (kernel 6.6+ with BTF is required)", err)
	}

	cleanup := func() {
		objs.Close()
	}

	excludePort := opts.ExcludePort
	if excludePort > 65535 {
		excludePort = 0
	}
	cfg := captureCaptureConfig{
		Enabled:     0,
		Snaplen:     opts.Snaplen,
		SampleRate:  opts.SampleRate,
		ExcludePort: excludePort,
	}
	if err := objs.CaptureCfg.Put(uint32(0), cfg); err != nil {
		cleanup()
		return fmt.Errorf("configure map: %w", err)
	}

	var links []link.Link
	var attachErrors []string
	ifaceNames := make(map[uint32]string, len(opts.Interfaces))
	for _, name := range opts.Interfaces {
		ifi, err := net.InterfaceByName(name)
		if err != nil {
			attachErrors = append(attachErrors, fmt.Sprintf("%s: %v", name, err))
			continue
		}
		ifaceNames[uint32(ifi.Index)] = name
		for _, dir := range []struct {
			prog   *ebpf.Program
			attach ebpf.AttachType
			label  string
		}{
			{objs.CaptureIngress, ebpf.AttachTCXIngress, "ingress"},
			{objs.CaptureEgress, ebpf.AttachTCXEgress, "egress"},
		} {
			l, err := link.AttachTCX(link.TCXOptions{
				Interface: ifi.Index,
				Program:   dir.prog,
				Attach:    dir.attach,
			})
			if err != nil {
				attachErrors = append(attachErrors, fmt.Sprintf("%s/%s: %v", name, dir.label, err))
				continue
			}
			links = append(links, l)
		}
	}

	if len(links) == 0 {
		cleanup()
		return fmt.Errorf("failed to attach to any interface: %s", strings.Join(attachErrors, "; "))
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		for _, l := range links {
			l.Close()
		}
		cleanup()
		return fmt.Errorf("open ring buffer: %w", err)
	}

	// Convert CLOCK_MONOTONIC timestamps to wall clock.
	now := time.Now()
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err == nil {
		m.wallOff = now.UnixNano() - ts.Nano()
	} else {
		m.wallOff = now.UnixNano()
	}

	cfg.Enabled = 1
	if err := objs.CaptureCfg.Put(uint32(0), cfg); err != nil {
		rd.Close()
		for _, l := range links {
			l.Close()
		}
		cleanup()
		return fmt.Errorf("enable capture: %w", err)
	}

	m.mu.Lock()
	m.objs = &objs
	m.reader = rd
	m.links = links
	m.opts = opts
	m.running = true
	m.start = time.Now()
	m.attachErrors = attachErrors
	m.lastError = ""
	m.lastKernelPackets, m.lastKernelBytes, m.lastKernelSkipped, m.lastKernelFiltered = 0, 0, 0, 0
	m.ifaceNames = ifaceNames
	m.mu.Unlock()

	m.wg.Add(1)
	go m.readLoop(rd)

	m.log.Info("capture started", "interfaces", opts.Interfaces, "snaplen", opts.Snaplen, "sampleRate", opts.SampleRate)
	return nil
}

// Stop ends the capture session. It is safe to call when not running.
func (m *Manager) Stop() {
	m.mu.Lock()
	objs := m.objs
	rd := m.reader
	links := m.links
	m.objs = nil
	m.reader = nil
	m.links = nil
	wasRunning := m.running
	m.running = false
	m.mu.Unlock()

	if !wasRunning && objs == nil {
		return
	}

	if objs != nil {
		// Disable capture first so no new events are produced.
		_ = objs.CaptureCfg.Put(uint32(0), captureCaptureConfig{Enabled: 0})
		pkts, bytes, skipped, filtered := readKernelStats(objs)
		m.mu.Lock()
		m.lastKernelPackets, m.lastKernelBytes, m.lastKernelSkipped = pkts, bytes, skipped
		m.lastKernelFiltered = filtered
		m.mu.Unlock()
	}
	for i := len(links) - 1; i >= 0; i-- {
		_ = links[i].Close()
	}
	if rd != nil {
		_ = rd.Close()
	}
	m.wg.Wait()
	if objs != nil {
		_ = objs.Close()
	}
	m.log.Info("capture stopped")
}

func (m *Manager) readLoop(rd *ringbuf.Reader) {
	defer m.wg.Done()
	var rec ringbuf.Record
	for {
		if err := rd.ReadInto(&rec); err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || errors.Is(err, os.ErrClosed) {
				return
			}
			m.mu.Lock()
			m.lastError = err.Error()
			m.mu.Unlock()
			m.log.Warn("ring buffer read failed", "err", err)
			return
		}
		if len(rec.RawSample) < eventHeaderLen {
			continue
		}
		sample := rec.RawSample
		ts := int64(binary.LittleEndian.Uint64(sample[0:8]))
		ifIndex := binary.LittleEndian.Uint32(sample[8:12])
		wireLen := binary.LittleEndian.Uint32(sample[12:16])
		capLen := binary.LittleEndian.Uint32(sample[16:20])
		dir := sample[22]
		flags := sample[23]

		if capLen > uint32(len(sample)-eventHeaderLen) {
			continue
		}
		if capLen == 0 {
			continue
		}
		data := make([]byte, capLen)
		copy(data, sample[eventHeaderLen:eventHeaderLen+capLen])

		p := &packet.Packet{
			Time:      time.Unix(0, ts+m.wallOff),
			IfIndex:   ifIndex,
			IfName:    m.ifaceName(ifIndex),
			Direction: packet.Direction(dir & 1),
			WireLen:   wireLen,
			CapLen:    capLen,
			Truncated: flags&1 != 0,
			LinkType:  packet.LinkEthernet,
			Data:      data,
		}
		m.store.Add(p)
	}
}

func (m *Manager) ifaceName(idx uint32) string {
	if name, ok := m.ifaceNames[idx]; ok {
		return name
	}
	return fmt.Sprintf("if%d", idx)
}

// Status returns the current session status.
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := Status{
		Running:      m.running,
		Interfaces:   append([]string(nil), m.opts.Interfaces...),
		Snaplen:      m.opts.Snaplen,
		SampleRate:   m.opts.SampleRate,
		RingSize:     m.opts.RingSize,
		ExcludePort:  m.opts.ExcludePort,
		AttachErrors: append([]string(nil), m.attachErrors...),
		LastError:    m.lastError,
	}
	if st.Interfaces == nil {
		st.Interfaces = []string{}
	}
	if m.running {
		st.UptimeSeconds = time.Since(m.start).Seconds()
	}
	if m.objs != nil {
		st.KernelPackets, st.KernelBytes, st.KernelSkipped, st.KernelFiltered = readKernelStats(m.objs)
	} else {
		st.KernelPackets = m.lastKernelPackets
		st.KernelBytes = m.lastKernelBytes
		st.KernelSkipped = m.lastKernelSkipped
		st.KernelFiltered = m.lastKernelFiltered
	}
	return st
}

func readKernelStats(objs *captureObjects) (packets, bytes, skipped, filtered uint64) {
	var per []captureCaptureStats
	if err := objs.Stats.Lookup(uint32(0), &per); err != nil {
		return 0, 0, 0, 0
	}
	for _, s := range per {
		packets += s.Packets
		bytes += s.Bytes
		skipped += s.Skipped
		filtered += s.Filtered
	}
	return packets, bytes, skipped, filtered
}
