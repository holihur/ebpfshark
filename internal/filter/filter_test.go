package filter

import (
	"net/netip"
	"testing"

	"ebpfshark/internal/packet"
)

func testMeta() *packet.Meta {
	body := []byte("GET /secret HTTP/1.1\r\nHost: example.com\r\n\r\n")
	return &packet.Meta{
		FrameLen:   200,
		CapLen:     200,
		Layers:     []string{"eth", "ip", "tcp", "http"},
		SrcIP:      netip.MustParseAddr("10.0.0.1"),
		DstIP:      netip.MustParseAddr("10.0.0.2"),
		SrcPort:    12345,
		DstPort:    80,
		EthSrc:     "02:00:00:00:00:01",
		EthDst:     "02:00:00:00:00:02",
		EthType:    0x0800,
		IPVersion:  4,
		IPProto:    6,
		TCPFlags:   0x10,
		TCPPayLen:  31,
		HTTPMethod: "GET",
		HTTPURI:    "/secret",
		HTTPHost:   "example.com",
		App:        "http",
		TLSSNI:     "example.com",
		DNSName:    "example.com",
		Payload:    body,
		Raw:        body,
	}
}

func TestFilters(t *testing.T) {
	m := testMeta()
	cases := []struct {
		expr string
		want bool
	}{
		{"", true},
		{"tcp", true},
		{"udp", false},
		{"http", true},
		{"dns", false},
		{"not tcp", false},
		{"tcp port 80", true},
		{"tcp port 443", false},
		{"port 80", true},
		{"portrange 70-90", true},
		{"portrange 100-200", false},
		{"src port 12345", true},
		{"src port 80", false},
		{"dst port 80", true},
		{"host 10.0.0.1", true},
		{"host 10.9.9.9", false},
		{"net 10.0.0.0/8", true},
		{"net 192.168.0.0/16", false},
		{"src host 10.0.0.1", true},
		{"dst host 10.0.0.1", false},
		{"ip.src == 10.0.0.1", true},
		{"ip.dst == 10.0.0.1", false},
		{"ip.addr == 10.0.0.2", true},
		{"ip.addr != 10.0.0.2", false},
		{"ip.proto == tcp", true},
		{"tcp.flags.syn == 0", true},
		{"tcp.flags.ack == 1", true},
		{"tcp.flags.rst == 1", false},
		{"frame.len > 100", true},
		{"len < 100", false},
		{"tcp.len > 20", true},
		{"eth.src == 02:00:00:00:00:01", true},
		{"eth.type == 0x0800", true},
		{"frame contains \"GET /secret\"", true},
		{"frame contains \"POST\"", false},
		{"http contains \"Host: example.com\"", true},
		{"http.request.method == \"GET\"", true},
		{"http.request.method == \"POST\"", false},
		{"http.request.uri contains \"secret\"", true},
		{"http.host == example.com", true},
		{"dns.qry.name contains example", false},
		{"tls.handshake.extensions_server_name == example.com", false},
		{"(tcp or udp) and not arp", true},
		{"tcp and (port 443 or port 8443)", false},
		{"tcp port 80 and ip.addr == 10.0.0.1", true},
	}
	for _, tc := range cases {
		f, err := Parse(tc.expr)
		if err != nil {
			t.Fatalf("Parse(%q): %v", tc.expr, err)
		}
		if got := f.Match(m); got != tc.want {
			t.Errorf("%q = %v, want %v", tc.expr, got, tc.want)
		}
	}
}

func TestDNSFilter(t *testing.T) {
	m := &packet.Meta{
		Layers:  []string{"eth", "ip", "udp", "dns"},
		SrcIP:   netip.MustParseAddr("10.0.0.1"),
		DstIP:   netip.MustParseAddr("8.8.8.8"),
		SrcPort: 50000,
		DstPort: 53,
		DNSName: "api.example.com",
		DNSID:   0x1234,
		App:     "dns",
	}
	for _, expr := range []string{
		"dns",
		"dns.qry.name contains example",
		"dns.id == 0x1234",
		"udp port 53",
		"dst port 53",
	} {
		f, err := Parse(expr)
		if err != nil {
			t.Fatalf("Parse(%q): %v", expr, err)
		}
		if !f.Match(m) {
			t.Errorf("%q should match", expr)
		}
	}
}

func TestInvalidFilters(t *testing.T) {
	for _, expr := range []string{
		"tcp.bogus == 1",
		"tcp and",
		"(tcp",
		"port notanumber",
		"host 999.1.1.1",
		"tcp contains",
		"ip.addr == not-an-ip",
		"portrange 100",
		"portrange 200-100",
		"&& tcp",
	} {
		if _, err := Parse(expr); err == nil {
			t.Errorf("Parse(%q) should fail", expr)
		}
	}
}

func TestIPv6Host(t *testing.T) {
	m := &packet.Meta{
		Layers: []string{"eth", "ipv6", "tcp"},
		SrcIP:  netip.MustParseAddr("2001:db8::1"),
		DstIP:  netip.MustParseAddr("2001:db8::2"),
	}
	for _, expr := range []string{"ipv6", "host 2001:db8::1", "net 2001:db8::/32", "ipv6.src == 2001:db8::1"} {
		f, err := Parse(expr)
		if err != nil {
			t.Fatalf("Parse(%q): %v", expr, err)
		}
		if !f.Match(m) {
			t.Errorf("%q should match IPv6 packet", expr)
		}
	}
	if f, _ := Parse("ip"); f.Match(m) {
		t.Error("ip filter must not match IPv6-only packet")
	}
}

func TestKnownFields(t *testing.T) {
	for _, f := range []string{"tcp.flags.syn", "dns.qry.name", "http.response.code", "frame.len"} {
		if !IsValidField(f) {
			t.Errorf("%s should be valid", f)
		}
	}
	if IsValidField("tcp.nope") {
		t.Error("tcp.nope should be invalid")
	}
	if len(KnownFields()) < 20 {
		t.Error("expected a populated field list")
	}
}

func TestNewProtocolFilters(t *testing.T) {
	names := []string{"ntp", "snmp", "syslog", "stun", "mqtt", "redis", "postgresql",
		"bgp", "ssh", "ssdp", "sip", "quic", "http2", "vxlan", "mpls", "gre",
		"igmp", "wireguard"}
	for _, name := range names {
		f, err := Parse(name)
		if err != nil {
			t.Fatalf("Parse(%q): %v", name, err)
		}
		if !f.Match(&packet.Meta{Layers: []string{name}}) {
			t.Errorf("%q should match its layer", name)
		}
	}
	if f, _ := Parse("postgres"); !f.Match(&packet.Meta{Layers: []string{"postgresql"}}) {
		t.Error("postgres alias should match postgresql")
	}
	if f, _ := Parse("wg"); !f.Match(&packet.Meta{Layers: []string{"wireguard"}}) {
		t.Error("wg alias should match wireguard")
	}
	f, err := Parse(`redis contains "SET"`)
	if err != nil {
		t.Fatal(err)
	}
	if !f.Match(&packet.Meta{Layers: []string{"redis"}, Payload: []byte("SET foo bar")}) {
		t.Error("redis contains should match payload")
	}
}
