package decode

import (
	"testing"

	"ebpfshark/internal/packet"
)

func benchHTTPFrame() []byte {
	body := []byte("GET /bench HTTP/1.1\r\nHost: bench.example\r\nUser-Agent: ebpfshark\r\n\r\n")
	return buildEthernet(buildIPv4(6, buildTCP(49152, 80, 0x18, body)), 0x0800)
}

func benchTLSFrame() []byte {
	return buildEthernet(buildIPv4(6, buildTCP(51000, 443, 0x18, buildClientHello("bench.example.com"))), 0x0800)
}

func benchDNSFrame() []byte {
	return buildEthernet(buildIPv4(17, buildUDP(53123, 53, buildDNSQuery(0x1234, "bench.example.com", 1))), 0x0800)
}

func BenchmarkDecodeHTTPDetail(b *testing.B) {
	frame := benchHTTPFrame()
	b.ReportAllocs()
	b.SetBytes(int64(len(frame)))
	for i := 0; i < b.N; i++ {
		res := Decode(frame, packet.LinkEthernet, len(frame))
		ReleaseFields(res.Fields)
	}
}

func BenchmarkDecodeHTTPSummary(b *testing.B) {
	frame := benchHTTPFrame()
	b.ReportAllocs()
	b.SetBytes(int64(len(frame)))
	for i := 0; i < b.N; i++ {
		_, _ = DecodeSummary(frame, packet.LinkEthernet, len(frame))
	}
}

func BenchmarkDecodeTLSHandshake(b *testing.B) {
	frame := benchTLSFrame()
	b.ReportAllocs()
	b.SetBytes(int64(len(frame)))
	for i := 0; i < b.N; i++ {
		res := Decode(frame, packet.LinkEthernet, len(frame))
		ReleaseFields(res.Fields)
	}
}

func BenchmarkDecodeDNS(b *testing.B) {
	frame := benchDNSFrame()
	b.ReportAllocs()
	b.SetBytes(int64(len(frame)))
	for i := 0; i < b.N; i++ {
		res := Decode(frame, packet.LinkEthernet, len(frame))
		ReleaseFields(res.Fields)
	}
}
