package decode

import (
	"encoding/binary"
	"strings"
	"testing"

	"ebpfshark/internal/packet"
)

func appCtx(b []byte) *ctx {
	return &ctx{data: b, m: packet.Meta{}}
}

func ber(tag byte, v []byte) []byte {
	out := []byte{tag, byte(len(v))}
	return append(out, v...)
}

func TestNTP(t *testing.T) {
	b := make([]byte, 48)
	b[0] = 0x1b // LI 0, VN 3, mode 3 (client)
	b[1] = 2
	b[2] = 6
	b[3] = 0xec
	c := appCtx(b)
	if !c.dissectNTP(b, 0) {
		t.Fatal("NTP not recognized")
	}
	if c.proto != "ntp" || !strings.Contains(c.appInfo, "client") {
		t.Fatalf("proto=%q info=%q", c.proto, c.appInfo)
	}
}

func TestSyslog(t *testing.T) {
	b := []byte("<34>1 2026-10-21T12:00:00Z host app 123 ID47 - hello world")
	c := appCtx(b)
	if !c.dissectSyslog(b, 0) {
		t.Fatal("syslog not recognized")
	}
	if c.proto != "syslog" || !strings.Contains(c.appInfo, "auth.crit") {
		t.Fatalf("proto=%q info=%q", c.proto, c.appInfo)
	}
}

func TestSTUN(t *testing.T) {
	b := make([]byte, 20)
	binary.BigEndian.PutUint16(b[0:2], 0x0001)
	binary.BigEndian.PutUint32(b[4:8], stunMagic)
	copy(b[8:20], []byte("0123456789ab"))
	c := appCtx(b)
	if !c.dissectSTUN(b, 0) {
		t.Fatal("STUN not recognized")
	}
	if c.proto != "stun" || !strings.Contains(c.appInfo, "Binding") {
		t.Fatalf("proto=%q info=%q", c.proto, c.appInfo)
	}
}

func TestMQTT(t *testing.T) {
	body := []byte{0, 4, 'M', 'Q', 'T', 'T', 4, 2, 0, 60, 0, 3, 'c', 'i', 'd'}
	b := append([]byte{0x10, byte(len(body))}, body...)
	c := appCtx(b)
	if !c.dissectMQTT(b, 0) {
		t.Fatal("MQTT not recognized")
	}
	if c.proto != "mqtt" || !strings.Contains(c.appInfo, "client=cid") {
		t.Fatalf("proto=%q info=%q", c.proto, c.appInfo)
	}
}

func TestRedis(t *testing.T) {
	b := []byte("*3\r\n$3\r\nSET\r\n$3\r\nfoo\r\n$3\r\nbar\r\n")
	c := appCtx(b)
	if !c.dissectRedis(b, 0) {
		t.Fatal("Redis not recognized")
	}
	if c.proto != "redis" || !strings.Contains(c.appInfo, "SET foo bar") {
		t.Fatalf("proto=%q info=%q", c.proto, c.appInfo)
	}
}

func TestPostgreSQL(t *testing.T) {
	payload := []byte("user\x00alice\x00database\x00test\x00\x00")
	b := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint32(b[0:4], uint32(len(b)))
	binary.BigEndian.PutUint32(b[4:8], 196608)
	copy(b[8:], payload)
	c := appCtx(b)
	if !c.dissectPostgreSQL(b, 0) {
		t.Fatal("PostgreSQL not recognized")
	}
	if c.proto != "postgresql" || !strings.Contains(c.appInfo, "alice") {
		t.Fatalf("proto=%q info=%q", c.proto, c.appInfo)
	}
}

func TestBGP(t *testing.T) {
	b := make([]byte, 19)
	for i := 0; i < 16; i++ {
		b[i] = 0xff
	}
	binary.BigEndian.PutUint16(b[16:18], 19)
	b[18] = 4 // KEEPALIVE
	c := appCtx(b)
	if !c.dissectBGP(b, 0) {
		t.Fatal("BGP not recognized")
	}
	if c.proto != "bgp" || !strings.Contains(c.appInfo, "KEEPALIVE") {
		t.Fatalf("proto=%q info=%q", c.proto, c.appInfo)
	}
}

func TestWireGuard(t *testing.T) {
	b := make([]byte, 16)
	b[0] = 4 // transport data
	binary.BigEndian.PutUint32(b[4:8], 42)
	c := appCtx(b)
	if !c.dissectWireGuard(b, 0) {
		t.Fatal("WireGuard not recognized")
	}
	if c.proto != "wireguard" || !strings.Contains(c.appInfo, "transport data") {
		t.Fatalf("proto=%q info=%q", c.proto, c.appInfo)
	}
}

func TestSNMP(t *testing.T) {
	oid := []byte{0x2b, 6, 1, 2, 1, 1, 1, 0} // 1.3.6.1.2.1.1.1.0
	varbind := ber(0x30, append(ber(0x06, oid), ber(0x05, nil)...))
	varbinds := ber(0x30, varbind)
	pduBody := append(ber(0x02, []byte{1}), append(ber(0x02, []byte{0}), append(ber(0x02, []byte{0}), varbinds...)...)...)
	pdu := ber(0xA0, pduBody)
	msg := append(ber(0x02, []byte{1}), ber(0x04, []byte("public"))...)
	msg = append(msg, pdu...)
	b := ber(0x30, msg)
	c := appCtx(b)
	if !c.dissectSNMP(b, 0) {
		t.Fatal("SNMP not recognized")
	}
	if c.proto != "snmp" || !strings.Contains(c.appInfo, "GET-REQUEST") || !strings.Contains(c.appInfo, "1.3.6.1.2.1.1.1.0") {
		t.Fatalf("proto=%q info=%q", c.proto, c.appInfo)
	}
}

func TestSSDP(t *testing.T) {
	b := []byte("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nST: ssdp:all\r\n\r\n")
	c := appCtx(b)
	if !c.dissectSSDP(b, 0) {
		t.Fatal("SSDP not recognized")
	}
	if c.proto != "ssdp" || !strings.Contains(c.appInfo, "M-SEARCH") || !strings.Contains(c.appInfo, "ssdp:all") {
		t.Fatalf("proto=%q info=%q", c.proto, c.appInfo)
	}
}

func TestSIP(t *testing.T) {
	b := []byte("INVITE sip:bob@example.com SIP/2.0\r\nCall-ID: abc\r\nCSeq: 1 INVITE\r\n\r\n")
	c := appCtx(b)
	if !c.dissectSIP(b, 0) {
		t.Fatal("SIP not recognized")
	}
	if c.proto != "sip" || !strings.Contains(c.appInfo, "Call-ID=abc") {
		t.Fatalf("proto=%q info=%q", c.proto, c.appInfo)
	}
}

func TestSSH(t *testing.T) {
	b := []byte("SSH-2.0-OpenSSH_9.6\r\n")
	c := appCtx(b)
	if !c.dissectSSH(b, 0) {
		t.Fatal("SSH not recognized")
	}
	if c.proto != "ssh" || !strings.Contains(c.appInfo, "OpenSSH_9.6") {
		t.Fatalf("proto=%q info=%q", c.proto, c.appInfo)
	}
}

func TestHTTP2(t *testing.T) {
	b := append([]byte{}, http2Preface...)
	b = append(b, 0, 0, 0, 4, 0, 0, 0, 0, 0)
	c := appCtx(b)
	if !c.dissectHTTP2(b, 0) {
		t.Fatal("HTTP/2 not recognized")
	}
	if c.proto != "http2" || !strings.Contains(c.appInfo, "SETTINGS") {
		t.Fatalf("proto=%q info=%q", c.proto, c.appInfo)
	}
}

func TestQUIC(t *testing.T) {
	b := []byte{0xc0, 0, 0, 0, 1, 4, 1, 2, 3, 4, 4, 5, 6, 7, 8, 0, 0}
	c := appCtx(b)
	if !c.dissectQUIC(b, 0) {
		t.Fatal("QUIC not recognized")
	}
	if c.proto != "quic" || !strings.Contains(c.appInfo, "Initial") || !strings.Contains(c.appInfo, "v1") {
		t.Fatalf("proto=%q info=%q", c.proto, c.appInfo)
	}
}

func TestVXLAN(t *testing.T) {
	inner := buildEthernet(buildIPv4(17, buildUDP(1234, 53, buildDNSQuery(1, "example.com", 1))), 0x0800)
	b := make([]byte, 8)
	b[0] = 0x08
	binary.BigEndian.PutUint32(b[4:8], 100<<8)
	b = append(b, inner...)
	c := appCtx(b)
	if !c.dissectVXLAN(b, 0) {
		t.Fatal("VXLAN not recognized")
	}
	if c.proto != "vxlan" || !strings.Contains(c.appInfo, "VNI 100") {
		t.Fatalf("proto=%q info=%q", c.proto, c.appInfo)
	}
}

func TestIGMP(t *testing.T) {
	b := []byte{0x11, 100, 0, 0, 224, 0, 0, 1}
	c := appCtx(b)
	c.dissectIGMP(b, 0)
	if c.proto != "igmp" || !strings.Contains(c.appInfo, "224.0.0.1") {
		t.Fatalf("proto=%q info=%q", c.proto, c.appInfo)
	}
}

func TestMPLS(t *testing.T) {
	inner := buildIPv4(6, buildTCP(1234, 80, 0x18, []byte("x")))
	label := make([]byte, 4)
	binary.BigEndian.PutUint32(label, (100<<12)|(1<<8)|64)
	b := append(label, inner...)
	c := appCtx(b)
	c.dissectMPLS(b, 0)
	if c.proto != "mpls" || c.m.SrcPort != 1234 {
		t.Fatalf("proto=%q srcport=%d info=%q", c.proto, c.m.SrcPort, c.appInfo)
	}
}

func TestGRE(t *testing.T) {
	inner := buildIPv4(6, buildTCP(5555, 443, 0x18, []byte("x")))
	b := []byte{0, 0, 0x08, 0x00}
	b = append(b, inner...)
	c := appCtx(b)
	c.dissectGRE(b, 0)
	if c.proto != "gre" || c.m.SrcPort != 5555 {
		t.Fatalf("proto=%q srcport=%d info=%q", c.proto, c.m.SrcPort, c.appInfo)
	}
}

func fieldLabels(fields []*Field) []string {
	var out []string
	for _, f := range fields {
		out = append(out, f.Label)
		out = append(out, fieldLabels(f.Children)...)
	}
	return out
}

func containsLabel(labels []string, needle string) bool {
	for _, l := range labels {
		if strings.Contains(l, needle) {
			return true
		}
	}
	return false
}

func TestDHCPFullOptions(t *testing.T) {
	b := make([]byte, 240)
	b[0] = 1 // BOOTREQUEST
	b[1] = 1
	b[2] = 6
	binary.BigEndian.PutUint32(b[4:8], 0x12345678)
	copy(b[28:34], []byte{2, 0, 0, 0, 0, 1})
	binary.BigEndian.PutUint32(b[236:240], 0x63825363)
	opts := []byte{
		53, 1, 3,
		12, 4, 'h', 'o', 's', 't',
		50, 4, 10, 0, 0, 5,
		55, 3, 1, 3, 6,
		3, 4, 10, 0, 0, 1,
		6, 8, 8, 8, 8, 8, 1, 1, 1, 1,
		255,
	}
	b = append(b, opts...)
	c := appCtx(b)
	if !c.dissectDHCP(b, 0) {
		t.Fatal("DHCP not recognized")
	}
	if !strings.Contains(c.appInfo, "DHCP Request") || !strings.Contains(c.appInfo, "host") || !strings.Contains(c.appInfo, "requested=10.0.0.5") {
		t.Fatalf("info=%q", c.appInfo)
	}
	labels := fieldLabels(c.roots)
	for _, want := range []string{"DHCP Message Type", "Host Name", "Parameter Request List", "Domain Name Server"} {
		if !containsLabel(labels, want) {
			t.Errorf("missing option %q in %v", want, labels)
		}
	}
}

func TestIGMPv3Report(t *testing.T) {
	b := make([]byte, 24)
	b[0] = 0x22
	binary.BigEndian.PutUint16(b[6:8], 1)
	b[8] = 1 // MODE_IS_INCLUDE
	b[9] = 0
	binary.BigEndian.PutUint16(b[10:12], 1)
	copy(b[12:16], []byte{224, 0, 0, 1})
	copy(b[16:20], []byte{10, 0, 0, 1})
	c := appCtx(b)
	c.dissectIGMP(b, 0)
	if c.proto != "igmp" || !strings.Contains(c.appInfo, "records=1") {
		t.Fatalf("info=%q", c.appInfo)
	}
	if !containsLabel(fieldLabels(c.roots), "MODE_IS_INCLUDE") {
		t.Fatal("missing group record")
	}
}

func TestNTPExtension(t *testing.T) {
	b := make([]byte, 48)
	b[0] = 0x1b
	ext := []byte{0x01, 0x04, 0, 8, 'a', 'b', 'c', 'd'}
	b = append(b, ext...)
	c := appCtx(b)
	if !c.dissectNTP(b, 0) {
		t.Fatal("NTP not recognized")
	}
	if !containsLabel(fieldLabels(c.roots), "RATE") {
		t.Fatal("missing NTP extension field")
	}
}

func TestWireGuardHandshake(t *testing.T) {
	b := make([]byte, 148)
	b[0] = 1
	binary.BigEndian.PutUint32(b[4:8], 7)
	c := appCtx(b)
	if !c.dissectWireGuard(b, 0) {
		t.Fatal("WireGuard not recognized")
	}
	if !strings.Contains(c.appInfo, "handshake initiation") {
		t.Fatalf("info=%q", c.appInfo)
	}
	if !containsLabel(fieldLabels(c.roots), "Sender Index") || !containsLabel(fieldLabels(c.roots), "MAC1") {
		t.Fatal("missing WireGuard handshake fields")
	}
}

func TestSTUNError(t *testing.T) {
	b := make([]byte, 20)
	binary.BigEndian.PutUint16(b[0:2], 0x0111) // Binding error response
	binary.BigEndian.PutUint32(b[4:8], stunMagic)
	copy(b[8:20], []byte("0123456789ab"))
	attr := []byte{0, 9, 0, 8, 0, 0, 4, 4, 'd', 'e', 'n', 'y'}
	binary.BigEndian.PutUint16(b[2:4], 12)
	b = append(b, attr...)
	c := appCtx(b)
	if !c.dissectSTUN(b, 0) {
		t.Fatal("STUN not recognized")
	}
	if !strings.Contains(c.appInfo, "error response") {
		t.Fatalf("info=%q", c.appInfo)
	}
	if !containsLabel(fieldLabels(c.roots), "Error: 404") {
		t.Fatal("missing STUN error code")
	}
}

func TestMQTTV5Publish(t *testing.T) {
	body := []byte{0, 1, 't', 0x03, 0x23, 0x00, 0x01, 'h', 'i'}
	b := append([]byte{0x30, byte(len(body))}, body...)
	c := appCtx(b)
	if !c.dissectMQTT(b, 0) {
		t.Fatal("MQTT not recognized")
	}
	if !strings.Contains(c.appInfo, "PUBLISH") {
		t.Fatalf("info=%q", c.appInfo)
	}
	if !containsLabel(fieldLabels(c.roots), "Topic Alias") {
		t.Fatal("missing topic alias property")
	}
}

func TestPostgreSQLDataRow(t *testing.T) {
	payload := []byte{0, 1, 0, 0, 0, 2, 'h', 'i'}
	b := make([]byte, 5+len(payload))
	b[0] = 'D'
	binary.BigEndian.PutUint32(b[1:5], uint32(4+len(payload)))
	copy(b[5:], payload)
	c := appCtx(b)
	if !c.dissectPostgreSQL(b, 0) {
		t.Fatal("PostgreSQL not recognized")
	}
	if !strings.Contains(c.appInfo, "rows=1") {
		t.Fatalf("info=%q", c.appInfo)
	}
	if !containsLabel(fieldLabels(c.roots), "Column 1: hi") {
		t.Fatal("missing data row column")
	}
}

func bgpFrame(typ byte, body []byte) []byte {
	m := make([]byte, 19+len(body))
	for i := 0; i < 16; i++ {
		m[i] = 0xff
	}
	binary.BigEndian.PutUint16(m[16:18], uint16(len(m)))
	m[18] = typ
	copy(m[19:], body)
	return m
}

func TestBGPOpenAndUpdate(t *testing.T) {
	open := []byte{4, 0xfd, 0xe8, 0, 180, 1, 1, 1, 1, 14, 2, 12, 65, 4, 0, 0, 0xfd, 0xe9, 1, 4, 0, 1, 0, 1}
	c := appCtx(bgpFrame(1, open))
	if !c.dissectBGP(bgpFrame(1, open), 0) {
		t.Fatal("BGP OPEN not recognized")
	}
	if !containsLabel(fieldLabels(c.roots), "4-octet ASN 65001") {
		t.Fatal("missing 4-byte ASN capability")
	}
	attrs := []byte{0x40, 1, 1, 0, 0x40, 2, 6, 2, 1, 0, 0, 0xfd, 0xe9, 0x40, 3, 4, 192, 0, 2, 1}
	body := []byte{0, 2, 8, 10, 0, 20}
	body = append(body, attrs...)
	body = append(body, 24, 192, 0, 2)
	c = appCtx(bgpFrame(2, body))
	if !c.dissectBGP(bgpFrame(2, body), 0) {
		t.Fatal("BGP UPDATE not recognized")
	}
	if !strings.Contains(c.appInfo, "prefixes=1") {
		t.Fatalf("info=%q", c.appInfo)
	}
}
