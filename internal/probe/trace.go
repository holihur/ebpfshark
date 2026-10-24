// Package probe traces explicitly selected application functions with uprobes.
// It is intentionally narrow: callers name an executable and symbol; the
// tracer reports return latency and process metadata, not arbitrary arguments.
package probe

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"ebpfshark/internal/instrument"
)

// Function identifies one uprobe target.
type Function struct {
	Binary  string
	Symbol  string
	Address uint64 // explicit ELF address/offset; mutually exclusive with Symbol
}

// Options configures a tracing session. PID=0 traces all processes that load
// the target executable (subject to the target cgroup of the caller).
type Options struct {
	PID       int
	Functions []Function
}

// Event is one completed function call. It is an alias so the tracing service
// can share the event contract without importing the uprobe engine.
type Event = instrument.Event

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

// ParseFunctions is kept for the CLI/legacy callers. New code should use
// instrument.ParseTargets.
func ParseFunctions(s string) ([]Function, error) {
	targets, err := instrument.ParseTargets(s)
	if err != nil {
		return nil, err
	}
	out := make([]Function, 0, len(targets))
	for _, t := range targets {
		out = append(out, Function{Binary: t.Binary, Symbol: t.Symbol, Address: t.Address})
	}
	return out, nil
}

// Backend adapts the uprobe engine to instrument.Backend.
type Backend struct{}

func (Backend) Start(pid int, targets []instrument.Target) (instrument.Session, error) {
	functions := make([]Function, 0, len(targets))
	for _, t := range targets {
		functions = append(functions, Function{Binary: t.Binary, Symbol: t.Symbol, Address: t.Address})
	}
	return Start(Options{PID: pid, Functions: functions})
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
		if fn.Binary == "" {
			if opts.PID <= 0 {
				closeOnError()
				return nil, fmt.Errorf("empty binary requires -pid")
			}
			p, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", opts.PID))
			if err != nil {
				closeOnError()
				return nil, err
			}
			fn.Binary = strings.TrimSuffix(p, " (deleted)")
		}
		ex, err := link.OpenExecutable(fn.Binary)
		if err != nil {
			closeOnError()
			return nil, fmt.Errorf("%s: %w", fn.Binary, err)
		}
		cookie := uint64(i + 1)
		upOpts := &link.UprobeOptions{PID: opts.PID, Cookie: cookie, Address: fn.Address}
		symbol := fn.Symbol
		if fn.Address != 0 {
			symbol = ""
		}
		entry, err := ex.Uprobe(symbol, objs.ProbeEntry, upOpts)
		if err != nil {
			closeOnError()
			return nil, fmt.Errorf("%s:%s entry: %w", fn.Binary, fn.Symbol, err)
		}
		t.links = append(t.links, entry)
		ret, err := ex.Uretprobe(symbol, objs.ProbeReturn, upOpts)
		if err != nil {
			closeOnError()
			return nil, fmt.Errorf("%s:%s return: %w", fn.Binary, fn.Symbol, err)
		}
		t.links = append(t.links, ret)
		if fn.Symbol != "" {
			t.names[cookie] = fn.Symbol
		} else {
			t.names[cookie] = fmt.Sprintf("0x%x", fn.Address)
		}
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
		if len(rec.RawSample) < 57 {
			continue
		}
		b := rec.RawSample
		ts := int64(binary.LittleEndian.Uint64(b[0:8]))
		dur := binary.LittleEndian.Uint64(b[8:16])
		pid := binary.LittleEndian.Uint32(b[16:20])
		tid := binary.LittleEndian.Uint32(b[20:24])
		cookie := binary.LittleEndian.Uint64(b[24:32])
		cgroupID := binary.LittleEndian.Uint64(b[32:40])
		comm := strings.TrimRight(string(b[41:57]), "\x00")
		ev := Event{
			Time: time.Unix(0, ts+t.wallOff), Duration: time.Duration(dur),
			PID: pid, TID: tid, Function: t.names[cookie], Comm: comm, CgroupID: cgroupID,
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
