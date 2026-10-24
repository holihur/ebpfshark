package ipc

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

const (
	udsEventHeaderLen = 64
	defaultMaxPayload = 4096
	maxPayloadLimit   = 4096
	defaultRingSize   = 8 << 20
	maxRingSize       = 64 << 20
)

// TraceOptions configures one Unix-socket payload tracing session.
type TraceOptions struct {
	// PID limits tracing to one process (tgid). 0 traces every process.
	PID int
	// CgroupID limits tracing to one cgroup v2. 0 disables the cgroup filter.
	CgroupID uint64
	// MaxPayload is the number of payload bytes copied per event.
	MaxPayload uint32
	// RingSize is the BPF ring-buffer size in bytes.
	RingSize uint32
	// LogPath optionally appends events as JSONL while tracing. It is not
	// exposed through the HTTP start endpoint; only the server operator can
	// configure it.
	LogPath string `json:"-"`
}

// KernelStats are counters maintained by the eBPF programs.
type KernelStats struct {
	Events    uint64 `json:"events"`
	Bytes     uint64 `json:"bytes"`
	Truncated uint64 `json:"truncated"`
	Dropped   uint64 `json:"dropped"`
}

// Tracer owns the AF_UNIX fentry/fexit programs and their ring-buffer reader.
type Tracer struct {
	objs    *udsObjects
	links   []link.Link
	reader  *ringbuf.Reader
	wallOff int64

	mu       sync.Mutex
	closed   bool
	lastErr  string
	stats    KernelStats
	attachEr []string
	wg       sync.WaitGroup
	events   chan Event
}

// StartTracer loads the UDS programs and attaches send/receive probes. The
// receive hook (unix_stream_read_actor) is best effort: kernels that inline or
// rename it still get send-side tracing.
func StartTracer(opts TraceOptions) (*Tracer, error) {
	opts = NormalizeTraceOptions(opts)
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("raise memlock: %w", err)
	}
	spec, err := loadUds()
	if err != nil {
		return nil, err
	}
	if ms, ok := spec.Maps["uds_events"]; ok {
		ms.MaxEntries = opts.RingSize
	}
	var objs udsObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return nil, fmt.Errorf("load UDS eBPF objects: %w (kernel 6.6+ with BTF, fentry and CAP_BPF/CAP_PERFMON is required)", err)
	}
	cfg := udsUdsConfig{
		MaxPayload:   opts.MaxPayload,
		TargetPid:    uint32(opts.PID),
		TargetCgroup: opts.CgroupID,
	}
	if err := objs.UdsCfg.Put(uint32(0), cfg); err != nil {
		_ = objs.Close()
		return nil, fmt.Errorf("configure UDS map: %w", err)
	}

	t := &Tracer{
		objs:   &objs,
		events: make(chan Event, 1024),
	}
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err == nil {
		t.wallOff = time.Now().UnixNano() - ts.Nano()
	} else {
		t.wallOff = time.Now().UnixNano()
	}

	closeOnError := func() {
		for _, l := range t.links {
			_ = l.Close()
		}
		_ = objs.Close()
	}
	// fentry/fexit hooks are ABI independent and cover every AF_UNIX socket
	// family. A missing hook (for example an inlined static helper on an older
	// kernel) is recorded but does not prevent the remaining hooks from
	// working.
	for _, target := range []struct {
		name string
		prog *ebpf.Program
	}{
		{"unix_stream_sendmsg", objs.UdsSendStream},
		{"unix_dgram_sendmsg", objs.UdsSendDgram},
		{"unix_seqpacket_sendmsg", objs.UdsSendSeqpacket},
		{"unix_stream_read_actor", objs.UdsRecvStream},
		{"unix_dgram_recvmsg:enter", objs.UdsRecvDgramEnter},
		{"unix_dgram_recvmsg:exit", objs.UdsRecvDgramExit},
		{"unix_seqpacket_recvmsg:enter", objs.UdsRecvSeqpacketEnter},
		{"unix_seqpacket_recvmsg:exit", objs.UdsRecvSeqpacketExit},
	} {
		l, err := link.AttachTracing(link.TracingOptions{Program: target.prog})
		if err != nil {
			t.attachEr = append(t.attachEr, fmt.Sprintf("%s: %v", target.name, err))
			continue
		}
		t.links = append(t.links, l)
	}
	if len(t.links) == 0 {
		closeOnError()
		return nil, fmt.Errorf("attach UDS fentry/fexit hooks: %s", strings.Join(t.attachEr, "; "))
	}

	rd, err := ringbuf.NewReader(objs.UdsEvents)
	if err != nil {
		closeOnError()
		return nil, fmt.Errorf("open UDS ring buffer: %w", err)
	}
	t.reader = rd
	cfg.Enabled = 1
	if err := objs.UdsCfg.Put(uint32(0), cfg); err != nil {
		_ = rd.Close()
		closeOnError()
		return nil, fmt.Errorf("enable UDS tracing: %w", err)
	}
	t.wg.Add(1)
	go t.readLoop()
	return t, nil
}

// NormalizeTraceOptions applies safe defaults and bounds.
func NormalizeTraceOptions(opts TraceOptions) TraceOptions {
	if opts.PID < 0 {
		opts.PID = 0
	}
	if opts.MaxPayload == 0 {
		opts.MaxPayload = defaultMaxPayload
	}
	if opts.MaxPayload < 256 {
		opts.MaxPayload = 256
	}
	if opts.MaxPayload > maxPayloadLimit {
		opts.MaxPayload = maxPayloadLimit
	}
	if opts.RingSize == 0 {
		opts.RingSize = defaultRingSize
	}
	if opts.RingSize < 1<<16 {
		opts.RingSize = 1 << 16
	}
	if opts.RingSize > maxRingSize {
		opts.RingSize = maxRingSize
	}
	return opts
}

// Events returns the payload event stream. It is closed by Close.
func (t *Tracer) Events() <-chan Event { return t.events }

// AttachErrors returns non-fatal probe attachment failures.
func (t *Tracer) AttachErrors() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string(nil), t.attachEr...)
}

// LastError returns the last ring-buffer read error, if any.
func (t *Tracer) LastError() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.lastErr
}

// Stats returns a snapshot of the kernel-side counters, including counters
// captured at Close time.
func (t *Tracer) Stats() KernelStats {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.objs != nil {
		if st, ok := readKernelStats(t.objs); ok {
			t.stats = st
		}
	}
	return t.stats
}

func readKernelStats(objs *udsObjects) (KernelStats, bool) {
	var per []udsUdsStats
	if err := objs.UdsStatsMap.Lookup(uint32(0), &per); err != nil {
		return KernelStats{}, false
	}
	var out KernelStats
	for _, s := range per {
		out.Events += s.Events
		out.Bytes += s.Bytes
		out.Truncated += s.Truncated
		out.Dropped += s.Dropped
	}
	return out, true
}

func (t *Tracer) readLoop() {
	defer t.wg.Done()
	defer close(t.events)
	var rec ringbuf.Record
	for {
		if err := t.reader.ReadInto(&rec); err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || errors.Is(err, os.ErrClosed) {
				return
			}
			t.mu.Lock()
			t.lastErr = err.Error()
			t.mu.Unlock()
			return
		}
		if len(rec.RawSample) < udsEventHeaderLen {
			continue
		}
		b := rec.RawSample
		ts := int64(binary.LittleEndian.Uint64(b[0:8]))
		cgroupID := binary.LittleEndian.Uint64(b[8:16])
		inode := binary.LittleEndian.Uint64(b[16:24])
		pid := binary.LittleEndian.Uint32(b[24:28])
		tid := binary.LittleEndian.Uint32(b[28:32])
		capLen := binary.LittleEndian.Uint32(b[32:36])
		origLen := binary.LittleEndian.Uint32(b[36:40])
		direction := Direction(b[40])
		typeCode := b[41]
		truncated := b[42] != 0
		part := b[43]
		parts := b[44]
		comm := strings.TrimRight(string(b[48:udsEventHeaderLen]), "\x00")

		if inode == 0 {
			continue
		}
		if capLen > uint32(len(b)-udsEventHeaderLen) {
			continue
		}
		payload := make([]byte, capLen)
		copy(payload, b[udsEventHeaderLen:udsEventHeaderLen+capLen])
		ev := Event{
			Time:      time.Unix(0, ts+t.wallOff),
			Inode:     inode,
			PID:       pid,
			TID:       tid,
			CgroupID:  cgroupID,
			Comm:      comm,
			Direction: direction,
			Type:      socketTypeName(typeCode),
			TypeCode:  typeCode,
			Part:      part,
			Parts:     parts,
			Truncated: truncated || capLen < origLen,
			Payload:   payload,
		}
		select {
		case t.events <- ev:
		default:
			// The bounded userspace store is preferred over blocking the
			// ring-buffer reader; drop is visible in the store counters.
		}
	}
}

// Close detaches probes, stops the reader and preserves final statistics.
func (t *Tracer) Close() error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	t.closed = true
	objs := t.objs
	if objs != nil {
		_ = objs.UdsCfg.Put(uint32(0), udsUdsConfig{Enabled: 0})
		if st, ok := readKernelStats(objs); ok {
			t.stats = st
		}
		t.objs = nil
	}
	t.mu.Unlock()

	for _, l := range t.links {
		_ = l.Close()
	}
	if t.reader != nil {
		_ = t.reader.Close()
	}
	t.wg.Wait()
	if objs != nil {
		return objs.Close()
	}
	return nil
}
