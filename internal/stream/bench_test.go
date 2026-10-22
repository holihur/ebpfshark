package stream

import "testing"

func BenchmarkAssemblerInOrder(b *testing.B) {
	m := NewManager(DefaultBudget)
	payload := make([]byte, 1400)
	for i := 0; i < b.N; i++ {
		seq := uint32(i * len(payload))
		m.Add(tcpPacket("10.0.0.1", 12345, "10.0.0.2", 80, seq, 0x18, string(payload)))
	}
}
