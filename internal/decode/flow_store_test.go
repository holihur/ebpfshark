package decode

import "testing"

func TestFlowStoreBounded(t *testing.T) {
	var s flowStore[*tlsFlow]
	s.max = 8
	for i := 0; i < 100; i++ {
		key := string(rune('a' + i%26))
		f := s.GetOrCreate(key, func() *tlsFlow { return &tlsFlow{} })
		if f == nil {
			t.Fatal("nil flow")
		}
	}
	if got := s.count.Load(); got > s.max+1 {
		t.Fatalf("flow store grew to %d, max %d", got, s.max)
	}
}
