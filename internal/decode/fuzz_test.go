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

var protocolPorts = []uint16{
	22, 53, 80, 123, 161, 162, 179, 443, 514, 554, 1883, 1900, 1935,
	2055, 2056, 3306, 3478, 3479, 4739, 4789, 5432, 5672, 6379, 6343,
	8472, 8883, 9995, 1812, 1813, 1645, 1646, 5060, 51820, 47808, 4840,
}

func FuzzProtocolPayloads(f *testing.F) {
	seeds := [][]byte{
		[]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
		[]byte("$3\r\nSET\r\n"), []byte("\x16\x03\x01\x00\x00"),
		[]byte("MQTT"), []byte("SSH-2.0-test\r\n"),
	}
	for i, port := range protocolPorts {
		for _, payload := range seeds {
			f.Add(payload, uint8(i%2), uint8(i%256))
		}
		_ = port
	}
	f.Fuzz(func(t *testing.T, payload []byte, transport, app uint8) {
		port := protocolPorts[int(app)%len(protocolPorts)]
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
