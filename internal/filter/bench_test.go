package filter

import (
	"testing"

	"ebpfshark/internal/packet"
)

func BenchmarkFilterMatchTCPTLS(b *testing.B) {
	f, err := Parse("tcp port 443 and tls")
	if err != nil {
		b.Fatal(err)
	}
	m := packet.Meta{
		Layers:    []string{"eth", "ip", "tcp", "tls"},
		LayerMask: packet.LayerEth | packet.LayerIPv4 | packet.LayerTCP | packet.LayerTLS,
		SrcPort:   51000,
		DstPort:   443,
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if !f.Match(&m) {
			b.Fatal("filter should match")
		}
	}
}
