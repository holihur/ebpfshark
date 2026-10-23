package decode

import (
	"sync"
	"sync/atomic"
)

// flowStore is a bounded repository for per-connection dissector state.
// It is intentionally approximate: when the soft limit is exceeded a small
// batch of entries is evicted. This keeps long-running captures from growing
// TLS/HTTP2 state without putting a global lock on the hot path.
type flowStore[T any] struct {
	m     sync.Map
	count atomic.Int64
	max   int64
}

func (s *flowStore[T]) Get(key string) (T, bool) {
	if v, ok := s.m.Load(key); ok {
		return v.(T), true
	}
	var zero T
	return zero, false
}

func (s *flowStore[T]) GetOrCreate(key string, create func() T) T {
	if v, ok := s.m.Load(key); ok {
		return v.(T)
	}
	v := create()
	actual, loaded := s.m.LoadOrStore(key, v)
	if !loaded {
		if s.count.Add(1) > s.max && s.max > 0 {
			s.evict()
		}
	}
	return actual.(T)
}

func (s *flowStore[T]) evict() {
	target := s.max / 8
	if target < 1 {
		target = 1
	}
	var n int64
	s.m.Range(func(k, _ any) bool {
		s.m.Delete(k)
		n++
		return n < target
	})
	s.count.Add(-n)
}
