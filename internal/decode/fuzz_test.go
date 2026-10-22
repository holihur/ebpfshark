package decode

import (
	"testing"

	"ebpfshark/internal/packet"
)

func FuzzDecode(f *testing.F) {
	f.Add([]byte{}, uint8(0))
	f.Add(benchHTTPFrame(), uint8(1))
	f.Add(benchTLSFrame(), uint8(2))
	f.Add(benchDNSFrame(), uint8(3))
	f.Fuzz(func(t *testing.T, data []byte, link uint8) {
		types := []packet.LinkType{packet.LinkEthernet, packet.LinkRaw, packet.LinkLinuxSLL, packet.LinkLinuxSLL2}
		res := Decode(data, types[int(link)%len(types)], len(data))
		ReleaseFields(res.Fields)
	})
}

func FuzzProtocolPayloads(f *testing.F) {
	f.Add([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"), uint8(0), uint8(0))
	f.Add([]byte("hello"), uint8(1), uint8(1))
	f.Fuzz(func(t *testing.T, payload []byte, transport, app uint8) {
		ports := []uint16{53, 80, 443, 1883, 5432, 6379, 179, 22, 5060, 123}
		port := ports[int(app)%len(ports)]
		var frame []byte
		if transport&1 == 0 {
			frame = buildEthernet(buildIPv4(6, buildTCP(40000, port, 0x18, payload)), 0x0800)
		} else {
			frame = buildEthernet(buildIPv4(17, buildUDP(40000, port, payload)), 0x0800)
		}
		res := Decode(frame, packet.LinkEthernet, len(frame))
		ReleaseFields(res.Fields)
	})
}
