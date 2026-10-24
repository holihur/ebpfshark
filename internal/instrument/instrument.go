// Package instrument defines the stable contract between the tracing service
// and pluggable application instrumentation backends (uprobe, USDT, ...).
package instrument

import "time"

// Target identifies one application function to instrument.
type Target struct {
	PID     int
	Binary  string
	Symbol  string
	Address uint64 // explicit ELF address/offset; mutually exclusive with Symbol
}

// Event is one completed instrumented call.
type Event struct {
	Time     time.Time
	Duration time.Duration
	PID      uint32
	TID      uint32
	Function string
	Comm     string
	CgroupID uint64
}

// Session is a running instrumentation session.
type Session interface {
	Events() <-chan Event
	Close() error
}

// Backend creates sessions for a set of targets. Implementations may be
// uprobe-based, USDT-based, or a fake for tests.
type Backend interface {
	Start(pid int, targets []Target) (Session, error)
}
