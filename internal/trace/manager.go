// Package trace owns a function-call tracing session and its bounded event
// history. It is shared by the HTTP API, MCP tools and the CLI.
package trace

import (
	"sync"
	"time"

	"ebpfshark/internal/probe"
)

// Event is a completed traced function call.
type Event struct {
	ID         uint64 `json:"id"`
	Time       int64  `json:"time"`
	DurationNS int64  `json:"durationNs"`
	PID        uint32 `json:"pid"`
	TID        uint32 `json:"tid"`
	Function   string `json:"function"`
	Comm       string `json:"comm"`
}

// Status describes the current or last trace session.
type Status struct {
	Running   bool      `json:"running"`
	PID       int       `json:"pid"`
	Functions []string  `json:"functions"`
	Count     uint64    `json:"count"`
	StartedAt time.Time `json:"startedAt,omitempty"`
	Error     string    `json:"error,omitempty"`
}

// Manager serializes trace start/stop and keeps the last 10k events.
type Manager struct {
	mu      sync.Mutex
	tracer  *probe.Tracer
	pid     int
	funcs   []string
	events  []Event
	nextID  uint64
	count   uint64
	started time.Time
	errText string
	running bool
	wg      sync.WaitGroup
}

const maxEvents = 10000

func NewManager() *Manager { return &Manager{} }

// Start replaces any running trace session.
func (m *Manager) Start(pid int, functions []probe.Function) error {
	m.Stop()
	names := make([]string, 0, len(functions))
	for _, f := range functions {
		names = append(names, f.Binary+":"+f.Symbol)
	}
	t, err := probe.Start(probe.Options{PID: pid, Functions: functions})
	m.mu.Lock()
	m.pid, m.funcs, m.started, m.errText = pid, names, time.Now(), ""
	if err != nil {
		m.running = false
		m.mu.Unlock()
		return err
	}
	m.tracer = t
	m.running = true
	m.events = nil
	m.count = 0
	m.nextID = 0
	m.mu.Unlock()
	m.wg.Add(1)
	go m.readLoop(t)
	return nil
}

// Stop closes the current trace session.
func (m *Manager) Stop() {
	m.mu.Lock()
	t := m.tracer
	m.tracer = nil
	m.running = false
	m.mu.Unlock()
	if t != nil {
		_ = t.Close()
		m.wg.Wait()
	}
}

func (m *Manager) readLoop(t *probe.Tracer) {
	defer m.wg.Done()
	for ev := range t.Events() {
		m.mu.Lock()
		m.nextID++
		m.count++
		e := Event{
			ID: m.nextID, Time: ev.Time.UnixNano(), DurationNS: int64(ev.Duration),
			PID: ev.PID, TID: ev.TID, Function: ev.Function, Comm: ev.Comm,
		}
		m.events = append(m.events, e)
		if len(m.events) > maxEvents {
			m.events = append([]Event(nil), m.events[len(m.events)-maxEvents:]...)
		}
		m.mu.Unlock()
	}
}

// Status returns a snapshot.
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	return Status{
		Running: m.running, PID: m.pid, Functions: append([]string(nil), m.funcs...),
		Count: m.count, StartedAt: m.started, Error: m.errText,
	}
}

// Events returns events newer than after, at most limit.
func (m *Manager) Events(limit int, after uint64) ([]Event, Status) {
	if limit <= 0 || limit > 2000 {
		limit = 500
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Event, 0, min(limit, len(m.events)))
	for _, e := range m.events {
		if e.ID > after {
			out = append(out, e)
			if len(out) >= limit {
				break
			}
		}
	}
	st := Status{Running: m.running, PID: m.pid, Functions: append([]string(nil), m.funcs...), Count: m.count, StartedAt: m.started, Error: m.errText}
	return out, st
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
