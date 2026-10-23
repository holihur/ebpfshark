// Package probe traces explicitly selected application functions with uprobes.
// It is intentionally narrow: callers name an executable and symbol; the
// tracer reports return latency and process metadata, not arbitrary arguments.
package probe

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// Function identifies one uprobe target.
type Function struct {
	Binary string
	Symbol string
}

// Options configures a tracing session. PID=0 traces all processes that load
// the target executable (subject to the target cgroup of the caller).
type Options struct {
	PID       int
	Functions []Function
}

// Event is one completed function call.
type Event struct {
	Time     time.Time
	Duration time.Duration
	PID      uint32
	TID      uint32
	Function string
	Comm     string
}

// Tracer owns uprobe programs and their ring buffer reader.
type Tracer struct {
	objs    *probeObjects
	links   []link.Link
	reader  *ringbuf.Reader
	names   map[uint64]string
	wallOff int64

	mu     sync.Mutex
	closed bool
	wg     sync.WaitGroup
	events chan Event
}

// ParseFunctions parses comma-separated binary:symbol entries. A symbol may
// contain colons, so the first colon separates the executable.
func ParseFunctions(s string) ([]Function, error) {
	var out []Function
	for _, item := range strings.Split(s, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		i := strings.IndexByte(item, ':')
		if i <= 0 || i == len(item)-1 {
			return nil, fmt.Errorf("invalid function %q (want binary:symbol)", item)
		}
		out = append(out, Function{Binary: item[:i], Symbol: item[i+1:]})
	}
	if len(out) == 0 {
		return nil, errors.New("no functions selected")
	}
	return out, nil
}

// Start loads the probe programs and attaches entry/return uprobes.
func Start(opts Options) (*Tracer, error) {
	if len(opts.Functions) == 0 {
		return nil, errors.New("no functions selected")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("raise memlock: %w", err)
	}
	spec, err := loadProbe()
	if err != nil {
		return nil, err
	}
	var objs probeObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return nil, fmt.Errorf("load probe objects: %w", err)
	}
	cleanup := func() { _ = objs.Close() }
	cfg := probeProbeConfig{TargetTgid: uint32(opts.PID)}
	if err := objs.ProbeCfg.Put(uint32(0), cfg); err != nil {
		cleanup()
		return nil, err
	}
	t := &Tracer{objs: &objs, names: make(map[uint64]string), events: make(chan Event, 1024)}
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
		cleanup()
	}
	for i, fn := range opts.Functions {
		ex, err := link.OpenExecutable(fn.Binary)
		if err != nil {
			closeOnError()
			return nil, fmt.Errorf("%s: %w", fn.Binary, err)
		}
		cookie := uint64(i + 1)
		upOpts := &link.UprobeOptions{PID: opts.PID, Cookie: cookie}
		entry, err := ex.Uprobe(fn.Symbol, objs.ProbeEntry, upOpts)
		if err != nil {
			closeOnError()
			return nil, fmt.Errorf("%s:%s entry: %w", fn.Binary, fn.Symbol, err)
		}
		t.links = append(t.links, entry)
		ret, err := ex.Uretprobe(fn.Symbol, objs.ProbeReturn, upOpts)
		if err != nil {
			closeOnError()
			return nil, fmt.Errorf("%s:%s return: %w", fn.Binary, fn.Symbol, err)
		}
		t.links = append(t.links, ret)
		t.names[cookie] = fn.Symbol
	}
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		closeOnError()
		return nil, err
	}
	t.reader = rd
	cfg.Enabled = 1
	if err := objs.ProbeCfg.Put(uint32(0), cfg); err != nil {
		_ = rd.Close()
		closeOnError()
		return nil, err
	}
	t.wg.Add(1)
	go t.readLoop()
	return t, nil
}

// Events returns the completion event stream. It is closed on Close.
func (t *Tracer) Events() <-chan Event { return t.events }

func (t *Tracer) readLoop() {
	defer t.wg.Done()
	defer close(t.events)
	var rec ringbuf.Record
	for {
		if err := t.reader.ReadInto(&rec); err != nil {
			return
		}
		if len(rec.RawSample) < 49 {
			continue
		}
		b := rec.RawSample
		ts := int64(binary.LittleEndian.Uint64(b[0:8]))
		dur := binary.LittleEndian.Uint64(b[8:16])
		pid := binary.LittleEndian.Uint32(b[16:20])
		tid := binary.LittleEndian.Uint32(b[20:24])
		cookie := binary.LittleEndian.Uint64(b[24:32])
		comm := strings.TrimRight(string(b[33:49]), "\x00")
		ev := Event{
			Time: time.Unix(0, ts+t.wallOff), Duration: time.Duration(dur),
			PID: pid, TID: tid, Function: t.names[cookie], Comm: comm,
		}
		select {
		case t.events <- ev:
		default:
		}
	}
}

// Close detaches all probes and stops the reader.
func (t *Tracer) Close() error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	t.closed = true
	t.mu.Unlock()
	for _, l := range t.links {
		_ = l.Close()
	}
	if t.reader != nil {
		_ = t.reader.Close()
	}
	t.wg.Wait()
	if t.objs != nil {
		return t.objs.Close()
	}
	return nil
}
