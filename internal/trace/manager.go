// Package trace owns a function-call tracing session and its bounded event
// history. It is shared by the HTTP API, MCP tools and the CLI.
package trace

import (
	"fmt"
	"sync"
	"time"

	"ebpfshark/internal/instrument"
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
	CgroupID   uint64 `json:"cgroupID,omitempty"`
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
	session instrument.Session
	backend instrument.Backend
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

func NewManager(backends ...instrument.Backend) *Manager {
	m := &Manager{}
	if len(backends) > 0 {
		m.backend = backends[0]
	}
	return m
}

// SetBackend installs the instrumentation backend. It is normally provided at
// construction time.
func (m *Manager) SetBackend(backend instrument.Backend) {
	m.mu.Lock()
	m.backend = backend
	m.mu.Unlock()
}

// Start replaces any running trace session.
func (m *Manager) Start(pid int, functions []instrument.Target) error {
	m.Stop()
	names := make([]string, 0, len(functions))
	for _, f := range functions {
		name := f.Binary + ":" + f.Symbol
		if f.Symbol == "" {
			name = f.Binary + ":0x" + fmt.Sprintf("%x", f.Address)
		}
		names = append(names, name)
	}
	m.mu.Lock()
	backend := m.backend
	m.mu.Unlock()
	if backend == nil {
		return fmt.Errorf("no instrumentation backend configured")
	}
	session, err := backend.Start(pid, functions)
	m.mu.Lock()
	m.pid, m.funcs, m.started, m.errText = pid, names, time.Now(), ""
	if err != nil {
		m.running = false
		m.mu.Unlock()
		return err
	}
	m.session = session
	m.running = true
	m.events = nil
	m.count = 0
	m.nextID = 0
	m.mu.Unlock()
	m.wg.Add(1)
	go m.readLoop(session)
	return nil
}

// Stop closes the current trace session.
func (m *Manager) Stop() {
	m.mu.Lock()
	session := m.session
	m.session = nil
	m.running = false
	m.mu.Unlock()
	if session != nil {
		_ = session.Close()
		m.wg.Wait()
	}
}

func (m *Manager) readLoop(session instrument.Session) {
	defer m.wg.Done()
	for ev := range session.Events() {
		m.mu.Lock()
		m.nextID++
		m.count++
		e := Event{
			ID: m.nextID, Time: ev.Time.UnixNano(), DurationNS: int64(ev.Duration),
			PID: ev.PID, TID: ev.TID, Function: ev.Function, Comm: ev.Comm, CgroupID: ev.CgroupID,
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
