package filter

// FieldSchema describes a filterable field for the visual filter builder.
type FieldSchema struct {
	Name    string   `json:"name"`
	Group   string   `json:"group"`
	Type    string   `json:"type"` // layer, string, number, ip, flag, enum, bytes
	Ops     []string `json:"ops,omitempty"`
	Values  []string `json:"values,omitempty"`
	Suggest []string `json:"suggest,omitempty"`
}

var (
	numOps    = []string{"==", "!=", "<", "<=", ">", ">="}
	flagOps   = []string{"==", "!="}
	ipOps     = []string{"==", "!="}
	strOps    = []string{"==", "!=", "contains"}
	bytesOps  = []string{"contains"}
	layerType = "layer"
)

// Schema returns the field catalog used by the filter builder UI.
func Schema() []FieldSchema {
	layer := func(name string) FieldSchema {
		return FieldSchema{Name: name, Group: "Protocol", Type: layerType}
	}
	num := func(name, group string) FieldSchema {
		return FieldSchema{Name: name, Group: group, Type: "number", Ops: numOps}
	}
	flag := func(name, group string) FieldSchema {
		return FieldSchema{Name: name, Group: group, Type: "flag", Ops: flagOps, Values: []string{"1", "0"}}
	}
	ip := func(name, group string) FieldSchema {
		return FieldSchema{Name: name, Group: group, Type: "ip", Ops: ipOps}
	}
	str := func(name, group string) FieldSchema {
		return FieldSchema{Name: name, Group: group, Type: "string", Ops: strOps}
	}
	bytes := func(name string) FieldSchema {
		return FieldSchema{Name: name, Group: "Payload", Type: "bytes", Ops: bytesOps}
	}

	return []FieldSchema{
		layer("ip"), layer("ipv6"), layer("tcp"), layer("udp"), layer("icmp"), layer("icmpv6"),
		layer("arp"), layer("dns"), layer("http"), layer("tls"), layer("dhcp"), layer("vlan"), layer("eth"),

		num("frame.len", "Frame"),
		num("frame.cap_len", "Frame"),
		num("frame.number", "Frame"),
		str("frame.protocols", "Frame"),

		str("eth.src", "Link"),
		str("eth.dst", "Link"),
		{Name: "eth.type", Group: "Link", Type: "enum", Ops: flagOps, Values: []string{"ip", "ipv6", "arp"}},
		num("vlan.id", "Link"),

		ip("ip.src", "Network"),
		ip("ip.dst", "Network"),
		ip("ip.addr", "Network"),
		ip("ipv6.src", "Network"),
		ip("ipv6.dst", "Network"),
		ip("ipv6.addr", "Network"),
		num("ip.version", "Network"),
		{Name: "ip.proto", Group: "Network", Type: "enum", Ops: flagOps, Values: []string{"tcp", "udp", "icmp", "icmpv6"}},
		num("ip.ttl", "Network"),
		num("ip.len", "Network"),
		num("ipv6.hlim", "Network"),

		num("tcp.srcport", "Transport"),
		num("tcp.dstport", "Transport"),
		num("tcp.port", "Transport"),
		flag("tcp.flags.syn", "Transport"),
		flag("tcp.flags.ack", "Transport"),
		flag("tcp.flags.fin", "Transport"),
		flag("tcp.flags.rst", "Transport"),
		flag("tcp.flags.psh", "Transport"),
		flag("tcp.flags.urg", "Transport"),
		flag("tcp.flags.ece", "Transport"),
		flag("tcp.flags.cwr", "Transport"),
		num("tcp.flags", "Transport"),
		num("tcp.seq", "Transport"),
		num("tcp.ack", "Transport"),
		num("tcp.window", "Transport"),
		num("tcp.len", "Transport"),
		num("udp.srcport", "Transport"),
		num("udp.dstport", "Transport"),
		num("udp.port", "Transport"),
		num("udp.length", "Transport"),

		num("icmp.type", "ICMP / ARP"),
		num("icmp.code", "ICMP / ARP"),
		num("icmpv6.type", "ICMP / ARP"),
		num("arp.opcode", "ICMP / ARP"),
		ip("arp.src.proto_ipv4", "ICMP / ARP"),
		ip("arp.dst.proto_ipv4", "ICMP / ARP"),

		num("dns.id", "Application"),
		flag("dns.flags.response", "Application"),
		str("dns.qry.name", "Application"),
		{
			Name:    "http.request.method",
			Group:   "Application",
			Type:    "string",
			Ops:     strOps,
			Suggest: []string{"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH"},
		},
		str("http.request.uri", "Application"),
		str("http.host", "Application"),
		num("http.response.code", "Application"),
		num("tls.handshake.type", "Application"),
		str("tls.handshake.extensions_server_name", "Application"),

		bytes("frame"), bytes("data"), bytes("payload"),
	}
}
