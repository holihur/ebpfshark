package decode

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"

	"ebpfshark/internal/packet"
)

var (
	srcMAC = []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	dstMAC = []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}
	srcIP  = netip.MustParseAddr("10.1.2.3")
	dstIP  = netip.MustParseAddr("93.184.216.34")
)

func buildEthernet(payload []byte, proto uint16) []byte {
	frame := make([]byte, 14+len(payload))
	copy(frame[0:6], dstMAC)
	copy(frame[6:12], srcMAC)
	binary.BigEndian.PutUint16(frame[12:14], proto)
	copy(frame[14:], payload)
	return frame
}

func buildIPv4(proto uint8, payload []byte) []byte {
	ip := make([]byte, 20+len(payload))
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
	binary.BigEndian.PutUint16(ip[4:6], 0x1234)
	ip[8] = 64
	ip[9] = proto
	s4, d4 := srcIP.As4(), dstIP.As4()
	copy(ip[12:16], s4[:])
	copy(ip[16:20], d4[:])
	binary.BigEndian.PutUint16(ip[10:12], checksum(ip[:20]))
	copy(ip[20:], payload)
	return ip
}

func buildTCP(sport, dport uint16, flags uint8, payload []byte) []byte {
	tcp := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(tcp[0:2], sport)
	binary.BigEndian.PutUint16(tcp[2:4], dport)
	binary.BigEndian.PutUint32(tcp[4:8], 1000)
	binary.BigEndian.PutUint32(tcp[8:12], 2000)
	tcp[12] = 5 << 4
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	copy(tcp[20:], payload)
	pseudo := pseudoHeaderSumV4(srcIP, dstIP, 6, len(tcp))
	binary.BigEndian.PutUint16(tcp[16:18], checksumPseudoWith(pseudo, tcp))
	return tcp
}

func buildUDP(sport, dport uint16, payload []byte) []byte {
	udp := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(udp[0:2], sport)
	binary.BigEndian.PutUint16(udp[2:4], dport)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], payload)
	return udp
}

func buildDNSQuery(id uint16, name string, qtype uint16) []byte {
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[0:2], id)
	binary.BigEndian.PutUint16(msg[2:4], 0x0100) // recursion desired
	binary.BigEndian.PutUint16(msg[4:6], 1)
	for _, label := range strings.Split(name, ".") {
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0)
	q := make([]byte, 4)
	binary.BigEndian.PutUint16(q[0:2], qtype)
	binary.BigEndian.PutUint16(q[2:4], 1)
	return append(msg, q...)
}

func buildClientHello(sni string) []byte {
	ext := make([]byte, 0)
	sniData := make([]byte, 0)
	sniData = append(sniData, 0, 0) // server name list length placeholder
	sniData = append(sniData, 0)    // host_name
	sniData = append(sniData, byte(len(sni)>>8), byte(len(sni)))
	sniData = append(sniData, sni...)
	binary.BigEndian.PutUint16(sniData[0:2], uint16(len(sniData)-2))
	ext = append(ext, 0, 0) // extension type server_name
	ext = append(ext, byte(len(sniData)>>8), byte(len(sniData)))
	ext = append(ext, sniData...)

	hello := make([]byte, 0)
	hello = append(hello, 0x03, 0x03)          // legacy version TLS1.2
	hello = append(hello, make([]byte, 32)...) // random
	hello = append(hello, 0)                   // session id length
	hello = append(hello, 0, 2, 0x13, 0x01)    // cipher suites
	hello = append(hello, 1, 0)                // compression methods
	hello = append(hello, byte(len(ext)>>8), byte(len(ext)))
	hello = append(hello, ext...)

	handshake := make([]byte, 4)
	handshake[0] = 1 // client_hello
	handshake[1] = byte(len(hello) >> 16)
	handshake[2] = byte(len(hello) >> 8)
	handshake[3] = byte(len(hello))
	handshake = append(handshake, hello...)

	record := make([]byte, 5)
	record[0] = 22 // handshake
	record[1] = 0x03
	record[2] = 0x01
	binary.BigEndian.PutUint16(record[3:5], uint16(len(handshake)))
	return append(record, handshake...)
}

func decodeFrame(t *testing.T, payload []byte) Result {
	t.Helper()
	res := Decode(buildEthernet(payload, 0x0800), packet.LinkEthernet, 14+len(payload))
	return res
}

func TestHTTPRequest(t *testing.T) {
	body := "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: ebpfshark-test\r\n\r\n"
	tcp := buildTCP(49152, 80, 0x18, []byte(body))
	res := decodeFrame(t, buildIPv4(6, tcp))

	if res.Summary.Protocol != "HTTP" {
		t.Fatalf("protocol = %q, want HTTP", res.Summary.Protocol)
	}
	if !strings.HasPrefix(res.Summary.Info, "GET /index.html") {
		t.Fatalf("unexpected info: %q", res.Summary.Info)
	}
	if string(res.Meta.TCPPayload) != body {
		t.Fatalf("tcp payload = %q", res.Meta.TCPPayload)
	}
	if res.Meta.HTTPMethod != "GET" || res.Meta.HTTPHost != "example.com" {
		t.Fatalf("unexpected meta: %+v", res.Meta)
	}
	if res.Summary.Src != "10.1.2.3:49152" || res.Summary.Dst != "93.184.216.34:80" {
		t.Fatalf("unexpected endpoints: %s -> %s", res.Summary.Src, res.Summary.Dst)
	}
	if len(res.Fields) < 4 {
		t.Fatalf("expected eth/ip/tcp/http tree, got %d roots", len(res.Fields))
	}
}

func TestTCPSYN(t *testing.T) {
	tcp := buildTCP(50000, 443, 0x02, nil)
	res := decodeFrame(t, buildIPv4(6, tcp))
	if res.Summary.Protocol != "TCP" {
		t.Fatalf("protocol = %q", res.Summary.Protocol)
	}
	if !strings.Contains(res.Summary.Info, "[SYN]") {
		t.Fatalf("info = %q", res.Summary.Info)
	}
	if res.Meta.TCPFlags != 0x02 {
		t.Fatalf("flags = %#x", res.Meta.TCPFlags)
	}
}

func TestDNSQuery(t *testing.T) {
	dns := buildDNSQuery(0xabcd, "example.com", 1)
	udp := buildUDP(53123, 53, dns)
	res := decodeFrame(t, buildIPv4(17, udp))

	if res.Summary.Protocol != "DNS" {
		t.Fatalf("protocol = %q", res.Summary.Protocol)
	}
	if res.Meta.DNSName != "example.com" || res.Meta.DNSID != 0xabcd {
		t.Fatalf("meta dns = %q id=%#x", res.Meta.DNSName, res.Meta.DNSID)
	}
	if got, want := res.Summary.Info, "Standard query 0xabcd A example.com"; got != want {
		t.Fatalf("info = %q, want %q", got, want)
	}
}

func TestTLSClientHelloSNI(t *testing.T) {
	tls := buildClientHello("example.com")
	tcp := buildTCP(51000, 443, 0x18, tls)
	res := decodeFrame(t, buildIPv4(6, tcp))

	if res.Summary.Protocol != "TLS" {
		t.Fatalf("protocol = %q", res.Summary.Protocol)
	}
	if res.Meta.TLSSNI != "example.com" {
		t.Fatalf("sni = %q", res.Meta.TLSSNI)
	}
	if !strings.Contains(res.Summary.Info, "Client Hello") {
		t.Fatalf("info = %q", res.Summary.Info)
	}
}

func TestARP(t *testing.T) {
	arp := make([]byte, 28)
	binary.BigEndian.PutUint16(arp[0:2], 1)
	binary.BigEndian.PutUint16(arp[2:4], 0x0800)
	arp[4], arp[5] = 6, 4
	binary.BigEndian.PutUint16(arp[6:8], 1)
	copy(arp[8:14], srcMAC)
	copy(arp[14:18], netip.MustParseAddr("10.1.2.3").AsSlice())
	copy(arp[18:24], dstMAC)
	copy(arp[24:28], netip.MustParseAddr("10.1.2.4").AsSlice())

	res := Decode(buildEthernet(arp, 0x0806), packet.LinkEthernet, 14+len(arp))
	if res.Summary.Protocol != "ARP" {
		t.Fatalf("protocol = %q", res.Summary.Protocol)
	}
	if !strings.Contains(res.Summary.Info, "Who has 10.1.2.4?") {
		t.Fatalf("info = %q", res.Summary.Info)
	}
	if res.Meta.ARPDstIP.String() != "10.1.2.4" {
		t.Fatalf("arp dst = %s", res.Meta.ARPDstIP)
	}
}

func TestRawIPDetection(t *testing.T) {
	tcp := buildTCP(1000, 22, 0x10, nil)
	raw := buildIPv4(6, tcp)
	// Feed L3 bytes but claim Ethernet; the decoder should detect the missing
	// link-layer header (tunnel capture).
	res := Decode(raw, packet.LinkEthernet, len(raw))
	if res.Meta.LinkType != packet.LinkRaw {
		t.Fatalf("link type = %d, want raw", res.Meta.LinkType)
	}
	if res.Summary.Protocol != "TCP" || res.Meta.SrcPort != 1000 {
		t.Fatalf("unexpected decode: %+v", res.Summary)
	}
}

func TestTruncatedFrame(t *testing.T) {
	body := "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
	frame := buildEthernet(buildIPv4(6, buildTCP(40000, 80, 0x18, []byte(body))), 0x0800)
	res := Decode(frame[:30], packet.LinkEthernet, len(frame))
	if res.Summary.Protocol == "" {
		t.Fatal("expected a protocol label for truncated frame")
	}
}
