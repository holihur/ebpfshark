// Package filter implements a Wireshark/tcpdump flavoured display filter
// language. Expressions are compiled once and evaluated against packet.Meta.
package filter

import (
	"bytes"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"ebpfshark/internal/packet"
)

// Filter is a compiled display filter.
type Filter interface {
	Match(*packet.Meta) bool
}

type matchAll struct{}

func (matchAll) Match(*packet.Meta) bool { return true }

// Parse compiles a display filter expression. An empty expression matches
// every packet.
func Parse(input string) (Filter, error) {
	p, err := newParser(input)
	if err != nil {
		return nil, err
	}
	if len(p.tokens) == 0 || (len(p.tokens) == 1 && p.tokens[0].kind == tokEOF) {
		return matchAll{}, nil
	}
	n, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.peek().kind != tokEOF {
		return nil, fmt.Errorf("unexpected %q at position %d", p.peek().text, p.peek().pos)
	}
	return n, nil
}

// ---------------------------------------------------------------- AST nodes

type andNode struct{ l, r Filter }

func (n andNode) Match(m *packet.Meta) bool { return n.l.Match(m) && n.r.Match(m) }

type orNode struct{ l, r Filter }

func (n orNode) Match(m *packet.Meta) bool { return n.l.Match(m) || n.r.Match(m) }

type notNode struct{ f Filter }

func (n notNode) Match(m *packet.Meta) bool { return !n.f.Match(m) }

type layerNode struct{ name string }

func (n layerNode) Match(m *packet.Meta) bool {
	switch n.name {
	case "ip":
		return m.HasLayer("ip")
	case "ipv6", "ip6":
		return m.HasLayer("ipv6")
	case "tcp":
		return m.HasLayer("tcp")
	case "udp":
		return m.HasLayer("udp")
	case "icmp":
		return m.HasLayer("icmp")
	case "icmpv6", "icmp6":
		return m.HasLayer("icmpv6")
	case "arp":
		return m.HasLayer("arp")
	case "dns":
		return m.HasLayer("dns")
	case "http":
		return m.HasLayer("http")
	case "tls", "ssl":
		return m.HasLayer("tls")
	case "dhcp":
		return m.HasLayer("dhcp")
	case "ntp":
		return m.HasLayer("ntp")
	case "snmp":
		return m.HasLayer("snmp")
	case "syslog":
		return m.HasLayer("syslog")
	case "stun":
		return m.HasLayer("stun")
	case "mqtt":
		return m.HasLayer("mqtt")
	case "redis":
		return m.HasLayer("redis")
	case "postgresql", "postgres":
		return m.HasLayer("postgresql")
	case "bgp":
		return m.HasLayer("bgp")
	case "ssh":
		return m.HasLayer("ssh")
	case "ssdp":
		return m.HasLayer("ssdp")
	case "sip":
		return m.HasLayer("sip")
	case "quic":
		return m.HasLayer("quic")
	case "http2":
		return m.HasLayer("http2")
	case "vxlan":
		return m.HasLayer("vxlan")
	case "mpls":
		return m.HasLayer("mpls")
	case "gre":
		return m.HasLayer("gre")
	case "igmp":
		return m.HasLayer("igmp")
	case "wireguard", "wg":
		return m.HasLayer("wireguard")
	case "sctp":
		return m.HasLayer("sctp")
	case "mysql":
		return m.HasLayer("mysql")
	case "radius":
		return m.HasLayer("radius")
	case "netflow":
		return m.HasLayer("netflow")
	case "rtp":
		return m.HasLayer("rtp")
	case "rtcp":
		return m.HasLayer("rtcp")
	case "websocket":
		return m.HasLayer("websocket")
	case "vlan":
		return m.HasLayer("vlan")
	case "eth":
		return m.HasLayer("eth")
	}
	return false
}

type portNode struct {
	dir    int // 0 any, 1 src, 2 dst
	lo, hi uint16
}

func (n portNode) Match(m *packet.Meta) bool {
	if !m.HasLayer("tcp") && !m.HasLayer("udp") {
		return false
	}
	p1, p2 := m.SrcPort, m.DstPort
	check := func(p uint16) bool { return p >= n.lo && p <= n.hi }
	switch n.dir {
	case 1:
		return check(p1)
	case 2:
		return check(p2)
	default:
		return check(p1) || check(p2)
	}
}

type hostNode struct {
	dir    int // 0 any, 1 src, 2 dst
	prefix netip.Prefix
}

func (n hostNode) Match(m *packet.Meta) bool {
	contains := func(a netip.Addr) bool {
		if !a.IsValid() || a.BitLen() != n.prefix.Addr().BitLen() {
			return false
		}
		return n.prefix.Contains(a)
	}
	switch n.dir {
	case 1:
		return contains(m.SrcIP) || contains(m.ARPSrcIP)
	case 2:
		return contains(m.DstIP) || contains(m.ARPDstIP)
	default:
		return contains(m.SrcIP) || contains(m.DstIP) || contains(m.ARPSrcIP) || contains(m.ARPDstIP)
	}
}

type cmpNode struct {
	field string
	op    string
	num   uint64
	str   string
	addr  netip.Prefix
}

func (n cmpNode) Match(m *packet.Meta) bool {
	f := n.field
	sv, haveS := stringField(m, f)
	if haveS {
		return matchString(sv, n.op, n.str)
	}
	if n.op == "contains" {
		switch f {
		case "frame":
			return bytes.Contains(m.Raw, []byte(n.str))
		case "tcp", "udp", "data", "http", "dns", "tls", "payload",
			"ntp", "snmp", "syslog", "stun", "mqtt", "redis", "postgresql",
			"bgp", "ssh", "ssdp", "sip", "quic", "http2", "vxlan", "mpls",
			"gre", "igmp", "wireguard":
			return bytes.Contains(m.Payload, []byte(n.str))
		}
		return false
	}
	if isPortField(f) {
		return matchPortField(m, f, n.op, n.num)
	}
	av, haveA := addrField(m, f)
	if haveA {
		if !av.IsValid() || av.BitLen() != n.addr.Addr().BitLen() {
			return false
		}
		ok := n.addr.Contains(av)
		if n.op == "!=" {
			return !ok
		}
		return ok
	}
	nv, haveN := numberField(m, f)
	if !haveN {
		return false
	}
	return matchNumber(nv, n.op, n.num)
}

func stringField(m *packet.Meta, f string) (string, bool) {
	switch f {
	case "eth.src", "eth.src.addr":
		return m.EthSrc, true
	case "eth.dst", "eth.dst.addr":
		return m.EthDst, true
	case "dns.qry.name", "dns.qry.name.raw":
		return m.DNSName, m.HasLayer("dns") && m.DNSName != ""
	case "http.request.method":
		return m.HTTPMethod, m.HasLayer("http") && m.HTTPMethod != ""
	case "http.request.uri":
		return m.HTTPURI, m.HasLayer("http") && m.HTTPURI != ""
	case "http.host", "http.request.full_uri":
		return m.HTTPHost, m.HasLayer("http") && m.HTTPHost != ""
	case "tls.handshake.extensions_server_name", "tls.handshake.extensions.server_name":
		return m.TLSSNI, m.HasLayer("tls") && m.TLSSNI != ""
	case "frame.protocols":
		return strings.Join(m.Layers, ":"), true
	case "protocol", "frame.protocol":
		return m.App, m.App != ""
	}
	return "", false
}

func addrField(m *packet.Meta, f string) (netip.Addr, bool) {
	switch f {
	case "ip.src", "ipv6.src", "ip6.src", "ip.src_host":
		return m.SrcIP, true
	case "ip.dst", "ipv6.dst", "ip6.dst", "ip.dst_host":
		return m.DstIP, true
	case "arp.src.proto_ipv4":
		return m.ARPSrcIP, true
	case "arp.dst.proto_ipv4":
		return m.ARPDstIP, true
	case "ip.addr", "ipv6.addr", "ip6.addr":
		// handled as a two-sided compare via special case below
		return netip.Addr{}, false
	}
	return netip.Addr{}, false
}

func numberField(m *packet.Meta, f string) (uint64, bool) {
	switch f {
	case "frame.len", "frame.len_frame":
		return uint64(m.FrameLen), true
	case "frame.cap_len":
		return uint64(m.CapLen), true
	case "frame.number":
		return m.Number, true
	case "vlan.id":
		return uint64(m.VLAN), m.HasLayer("vlan")
	case "eth.type":
		return uint64(m.EthType), true
	case "ip.version":
		return uint64(m.IPVersion), m.IPVersion != 0
	case "ip.proto", "ip.protocol":
		return uint64(m.IPProto), m.IPVersion != 0
	case "ip.ttl", "ipv6.hlim":
		return uint64(m.TTL), m.IPVersion != 0
	case "ip.len":
		return uint64(m.IPLen), m.IPVersion != 0
	case "tcp.srcport":
		return uint64(m.SrcPort), m.HasLayer("tcp")
	case "tcp.dstport":
		return uint64(m.DstPort), m.HasLayer("tcp")
	case "tcp.flags":
		return uint64(m.TCPFlags), m.HasLayer("tcp")
	case "tcp.flags.syn":
		return uint64(m.TCPFlags>>1) & 1, m.HasLayer("tcp")
	case "tcp.flags.ack":
		return uint64(m.TCPFlags>>4) & 1, m.HasLayer("tcp")
	case "tcp.flags.fin":
		return uint64(m.TCPFlags) & 1, m.HasLayer("tcp")
	case "tcp.flags.reset", "tcp.flags.rst":
		return uint64(m.TCPFlags>>2) & 1, m.HasLayer("tcp")
	case "tcp.flags.push", "tcp.flags.psh":
		return uint64(m.TCPFlags>>3) & 1, m.HasLayer("tcp")
	case "tcp.flags.urg":
		return uint64(m.TCPFlags>>5) & 1, m.HasLayer("tcp")
	case "tcp.flags.ece":
		return uint64(m.TCPFlags>>6) & 1, m.HasLayer("tcp")
	case "tcp.flags.cwr":
		return uint64(m.TCPFlags>>7) & 1, m.HasLayer("tcp")
	case "tcp.seq":
		return uint64(m.TCPSeq), m.HasLayer("tcp")
	case "tcp.ack":
		return uint64(m.TCPAck), m.HasLayer("tcp")
	case "tcp.window", "tcp.window_size_value":
		return uint64(m.TCPWin), m.HasLayer("tcp")
	case "tcp.len", "tcp.payload.len":
		return uint64(m.TCPPayLen), m.HasLayer("tcp")
	case "udp.srcport":
		return uint64(m.SrcPort), m.HasLayer("udp")
	case "udp.dstport":
		return uint64(m.DstPort), m.HasLayer("udp")
	case "udp.length":
		return uint64(m.UDPLen), m.HasLayer("udp")
	case "icmp.type":
		return uint64(m.ICMPType), m.HasLayer("icmp")
	case "icmp.code":
		return uint64(m.ICMPCode), m.HasLayer("icmp")
	case "icmpv6.type":
		return uint64(m.ICMPType), m.HasLayer("icmpv6")
	case "arp.opcode":
		return uint64(m.ARPOp), m.HasLayer("arp")
	case "dns.id":
		return uint64(m.DNSID), m.HasLayer("dns")
	case "dns.flags.response":
		if m.DNSResponse {
			return 1, m.HasLayer("dns")
		}
		return 0, m.HasLayer("dns")
	case "http.response.code":
		return uint64(m.HTTPCode), m.HTTPCode != 0
	case "tls.handshake.type":
		return uint64(m.TLSHandshake), m.HasLayer("tls")
	}
	return 0, false
}

func isPortField(f string) bool {
	switch f {
	case "tcp.port", "udp.port":
		return true
	}
	return false
}

func matchPortField(m *packet.Meta, f, op string, want uint64) bool {
	switch f {
	case "tcp.port":
		if !m.HasLayer("tcp") {
			return false
		}
		return matchNumber(uint64(m.SrcPort), op, want) || matchNumber(uint64(m.DstPort), op, want)
	case "udp.port":
		if !m.HasLayer("udp") {
			return false
		}
		return matchNumber(uint64(m.SrcPort), op, want) || matchNumber(uint64(m.DstPort), op, want)
	}
	return false
}

func matchNumber(v uint64, op string, want uint64) bool {
	switch op {
	case "==", "eq":
		return v == want
	case "!=", "ne":
		return v != want
	case "<", "lt":
		return v < want
	case "<=", "le":
		return v <= want
	case ">", "gt":
		return v > want
	case ">=", "ge":
		return v >= want
	}
	return false
}

func matchString(v string, op string, want string) bool {
	lv, lw := strings.ToLower(v), strings.ToLower(want)
	switch op {
	case "contains":
		return strings.Contains(lv, lw)
	case "matches":
		return lv == lw
	case "!=", "ne":
		return lv != lw
	}
	return lv == lw
}

// portNode and hostNode are combined with proto nodes for `tcp port 80`.

// ------------------------------------------------------------------- lexer

type tokKind int

const (
	tokEOF tokKind = iota
	tokIdent
	tokNumber
	tokLiteral
	tokString
	tokLParen
	tokRParen
	tokAnd
	tokOr
	tokNot
	tokEq
	tokNe
	tokLt
	tokLe
	tokGt
	tokGe
)

type token struct {
	kind tokKind
	text string
	num  uint64
	pos  int
}

func isIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isIdentChar(c byte) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == ':'
}

func isLiteralChar(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') ||
		c == '.' || c == ':' || c == '/' || c == '-' || c == 'x' || c == 'X'
}

func lex(input string) ([]token, error) {
	var out []token
	i := 0
	for i < len(input) {
		c := input[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			i++
			continue
		}
		start := i
		switch c {
		case '(':
			out = append(out, token{kind: tokLParen, text: "(", pos: i})
			i++
		case ')':
			out = append(out, token{kind: tokRParen, text: ")", pos: i})
			i++
		case '&':
			if i+1 < len(input) && input[i+1] == '&' {
				out = append(out, token{kind: tokAnd, text: "&&", pos: i})
				i += 2
			} else {
				return nil, fmt.Errorf("unexpected '&' at position %d (use &&)", i)
			}
		case '|':
			if i+1 < len(input) && input[i+1] == '|' {
				out = append(out, token{kind: tokOr, text: "||", pos: i})
				i += 2
			} else {
				return nil, fmt.Errorf("unexpected '|' at position %d (use ||)", i)
			}
		case '!':
			if i+1 < len(input) && input[i+1] == '=' {
				out = append(out, token{kind: tokNe, text: "!=", pos: i})
				i += 2
			} else {
				out = append(out, token{kind: tokNot, text: "!", pos: i})
				i++
			}
		case '=':
			if i+1 < len(input) && input[i+1] == '=' {
				i++
			}
			out = append(out, token{kind: tokEq, text: "==", pos: start})
			i++
		case '<':
			if i+1 < len(input) && input[i+1] == '=' {
				out = append(out, token{kind: tokLe, text: "<=", pos: i})
				i += 2
			} else {
				out = append(out, token{kind: tokLt, text: "<", pos: i})
				i++
			}
		case '>':
			if i+1 < len(input) && input[i+1] == '=' {
				out = append(out, token{kind: tokGe, text: ">=", pos: i})
				i += 2
			} else {
				out = append(out, token{kind: tokGt, text: ">", pos: i})
				i++
			}
		case '"', '\'':
			quote := c
			i++
			var sb strings.Builder
			closed := false
			for i < len(input) {
				if input[i] == '\\' && i+1 < len(input) {
					sb.WriteByte(input[i+1])
					i += 2
					continue
				}
				if input[i] == quote {
					i++
					closed = true
					break
				}
				sb.WriteByte(input[i])
				i++
			}
			if !closed {
				return nil, fmt.Errorf("unterminated string at position %d", start)
			}
			out = append(out, token{kind: tokString, text: sb.String(), pos: start})
		default:
			if isIdentStart(c) {
				for i < len(input) && isIdentChar(input[i]) {
					i++
				}
				text := input[start:i]
				out = append(out, token{kind: tokIdent, text: text, pos: start})
				continue
			}
			if (c >= '0' && c <= '9') || c == ':' {
				for i < len(input) && isLiteralChar(input[i]) {
					i++
				}
				text := input[start:i]
				if isAllDigits(text) {
					n, _ := strconv.ParseUint(text, 10, 64)
					out = append(out, token{kind: tokNumber, text: text, num: n, pos: start})
				} else {
					out = append(out, token{kind: tokLiteral, text: text, pos: start})
				}
				continue
			}
			return nil, fmt.Errorf("unexpected character %q at position %d", string(c), i)
		}
	}
	out = append(out, token{kind: tokEOF, text: "<end>", pos: len(input)})
	return out, nil
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// ------------------------------------------------------------------ parser

type parser struct {
	tokens []token
	pos    int
}

func newParser(input string) (*parser, error) {
	toks, err := lex(input)
	if err != nil {
		return nil, err
	}
	return &parser{tokens: toks}, nil
}

func (p *parser) peek() token { return p.tokens[p.pos] }
func (p *parser) next() token { t := p.tokens[p.pos]; p.pos++; return t }
func (p *parser) atEOF() bool { return p.peek().kind == tokEOF }
func (p *parser) accept(k tokKind) bool {
	if p.peek().kind == k {
		p.pos++
		return true
	}
	return false
}

func (p *parser) parseOr() (Filter, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for {
		t := p.peek()
		if t.kind == tokOr || (t.kind == tokIdent && strings.EqualFold(t.text, "or")) {
			p.next()
			right, err := p.parseAnd()
			if err != nil {
				return nil, err
			}
			left = orNode{left, right}
			continue
		}
		return left, nil
	}
}

func (p *parser) parseAnd() (Filter, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for {
		t := p.peek()
		if t.kind == tokAnd || (t.kind == tokIdent && strings.EqualFold(t.text, "and")) {
			p.next()
			right, err := p.parseUnary()
			if err != nil {
				return nil, err
			}
			left = andNode{left, right}
			continue
		}
		return left, nil
	}
}

func (p *parser) parseUnary() (Filter, error) {
	t := p.peek()
	if t.kind == tokNot || (t.kind == tokIdent && strings.EqualFold(t.text, "not")) {
		p.next()
		f, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return notNode{f}, nil
	}
	if t.kind == tokLParen {
		p.next()
		f, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if !p.accept(tokRParen) {
			return nil, fmt.Errorf("missing closing parenthesis at position %d", p.peek().pos)
		}
		return f, nil
	}
	return p.parsePredicate()
}

func isProtoName(s string) bool {
	switch s {
	case "tcp", "udp", "icmp", "icmpv6", "icmp6", "arp", "ip", "ipv6", "ip6",
		"dns", "http", "tls", "ssl", "dhcp", "vlan", "eth",
		"ntp", "snmp", "syslog", "stun", "mqtt", "redis", "postgresql", "postgres",
		"bgp", "ssh", "ssdp", "sip", "quic", "http2", "vxlan", "mpls", "gre",
		"igmp", "wireguard", "wg", "sctp", "mysql", "radius", "netflow",
		"rtp", "rtcp", "websocket":
		return true
	}
	return false
}

func (p *parser) parsePredicate() (Filter, error) {
	t := p.peek()
	if t.kind != tokIdent {
		return nil, fmt.Errorf("expected a protocol or field at position %d, got %q", t.pos, t.text)
	}
	name := strings.ToLower(t.text)

	if isProtoName(name) {
		p.next()
		// tcpdump style: `tcp port 443`, `udp src port 53`
		if p.peek().kind == tokIdent {
			nxt := strings.ToLower(p.peek().text)
			if nxt == "contains" || nxt == "matches" {
				return p.parseComparison(name)
			}
			if nxt == "port" || nxt == "host" || nxt == "net" || nxt == "src" || nxt == "dst" || nxt == "portrange" {
				q, err := p.parseQualifier()
				if err != nil {
					return nil, err
				}
				return andNode{layerNode{name}, q}, nil
			}
		}
		return layerNode{name}, nil
	}

	switch name {
	case "frame", "data", "payload":
		p.next()
		return p.parseComparison(name)
	case "host", "net", "port", "portrange", "src", "dst":
		return p.parseQualifier()
	case "len":
		p.next()
		return p.parseComparison("frame.len")
	case "proto":
		p.next()
		return p.parseComparison("ip.proto")
	case "contains":
		return nil, fmt.Errorf("contains needs a field or protocol on its left (position %d)", t.pos)
	}

	if !strings.Contains(t.text, ".") {
		return nil, fmt.Errorf("unknown protocol or field %q at position %d", t.text, t.pos)
	}
	p.next()
	return p.parseComparison(name)
}

// parseQualifier handles host/net/port/portrange, optionally prefixed with
// src or dst.
func (p *parser) parseQualifier() (Filter, error) {
	dir := 0
	if p.peek().kind == tokIdent {
		switch strings.ToLower(p.peek().text) {
		case "src":
			dir = 1
			p.next()
		case "dst":
			dir = 2
			p.next()
		}
	}
	t := p.peek()
	if t.kind != tokIdent {
		return nil, fmt.Errorf("expected host, net, port or portrange at position %d", t.pos)
	}
	kind := strings.ToLower(t.text)
	p.next()
	switch kind {
	case "host":
		addr, err := p.parseAddr()
		if err != nil {
			return nil, err
		}
		return hostNode{dir: dir, prefix: netip.PrefixFrom(addr, addr.BitLen())}, nil
	case "net":
		tok := p.next()
		if tok.kind != tokLiteral && tok.kind != tokIdent && tok.kind != tokString && tok.kind != tokNumber {
			return nil, fmt.Errorf("expected a network at position %d", tok.pos)
		}
		text := strings.TrimSpace(tok.text)
		if strings.Contains(text, "/") {
			prefix, err := netip.ParsePrefix(text)
			if err != nil {
				return nil, fmt.Errorf("invalid network %q", text)
			}
			return hostNode{dir: dir, prefix: prefix.Masked()}, nil
		}
		addr, err := netip.ParseAddr(text)
		if err != nil {
			return nil, fmt.Errorf("invalid network %q", text)
		}
		bits := addr.BitLen()
		if p.peek().kind == tokNumber || p.peek().kind == tokLiteral {
			if b, err := strconv.Atoi(p.peek().text); err == nil && b >= 0 && b <= bits {
				bits = b
				p.next()
			}
		}
		return hostNode{dir: dir, prefix: netip.PrefixFrom(addr, bits).Masked()}, nil
	case "port":
		n, err := p.parsePort()
		if err != nil {
			return nil, err
		}
		return portNode{dir: dir, lo: n, hi: n}, nil
	case "portrange":
		v := p.next()
		if v.kind != tokLiteral && v.kind != tokString && v.kind != tokNumber {
			return nil, fmt.Errorf("expected port range at position %d", v.pos)
		}
		parts := strings.SplitN(v.text, "-", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid port range %q", v.text)
		}
		lo, err1 := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 16)
		hi, err2 := strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 16)
		if err1 != nil || err2 != nil || lo > hi {
			return nil, fmt.Errorf("invalid port range %q", v.text)
		}
		return portNode{dir: dir, lo: uint16(lo), hi: uint16(hi)}, nil
	}
	return nil, fmt.Errorf("expected host, net, port or portrange at position %d", t.pos)
}

func (p *parser) parseAddr() (netip.Addr, error) {
	t := p.next()
	if t.kind != tokLiteral && t.kind != tokIdent && t.kind != tokString && t.kind != tokNumber {
		return netip.Addr{}, fmt.Errorf("expected an IP address at position %d", t.pos)
	}
	text := strings.TrimSpace(t.text)
	if addr, err := netip.ParseAddr(text); err == nil {
		return addr, nil
	}
	if prefix, err := netip.ParsePrefix(text); err == nil {
		return prefix.Addr(), nil
	}
	return netip.Addr{}, fmt.Errorf("invalid IP address %q", t.text)
}

func (p *parser) parsePort() (uint16, error) {
	t := p.peek()
	if t.kind != tokNumber && t.kind != tokLiteral {
		return 0, fmt.Errorf("expected a port number at position %d", t.pos)
	}
	n, err := strconv.ParseUint(t.text, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("invalid port %q", t.text)
	}
	p.next()
	return uint16(n), nil
}

func (p *parser) parseComparison(field string) (Filter, error) {
	if !IsValidField(field) {
		return nil, fmt.Errorf("unknown field %q", field)
	}
	opTok := p.peek()
	op := ""
	switch opTok.kind {
	case tokEq:
		op = "=="
	case tokNe:
		op = "!="
	case tokLt:
		op = "<"
	case tokLe:
		op = "<="
	case tokGt:
		op = ">"
	case tokGe:
		op = ">="
	case tokIdent:
		switch strings.ToLower(opTok.text) {
		case "eq":
			op = "=="
		case "ne":
			op = "!="
		case "lt":
			op = "<"
		case "le":
			op = "<="
		case "gt":
			op = ">"
		case "ge":
			op = ">="
		case "contains":
			op = "contains"
		case "matches":
			op = "matches"
		default:
			return nil, fmt.Errorf("expected a comparison operator at position %d, got %q", opTok.pos, opTok.text)
		}
	default:
		return nil, fmt.Errorf("expected a comparison operator at position %d, got %q", opTok.pos, opTok.text)
	}
	p.next()

	v := p.peek()
	if v.kind != tokNumber && v.kind != tokLiteral && v.kind != tokString && v.kind != tokIdent {
		return nil, fmt.Errorf("expected a value after %q at position %d", op, v.pos)
	}
	p.next()
	text := v.text

	n := cmpNode{field: field, op: op, str: text}

	switch {
	case isAddrField(field):
		if op != "==" && op != "!=" {
			return nil, fmt.Errorf("operator %q is not valid for %s", op, field)
		}
		if field == "ip.addr" || field == "ipv6.addr" || field == "ip6.addr" {
			addr, err := netip.ParseAddr(text)
			if err != nil {
				return nil, fmt.Errorf("invalid IP address %q", text)
			}
			any := hostNode{dir: 0, prefix: netip.PrefixFrom(addr, addr.BitLen())}
			if op == "!=" {
				return notNode{any}, nil
			}
			return any, nil
		}
		if strings.Contains(text, "/") {
			prefix, err := netip.ParsePrefix(text)
			if err != nil {
				return nil, fmt.Errorf("invalid network %q", text)
			}
			return cmpNode{field: field, op: op, addr: prefix.Masked()}, nil
		}
		addr, err := netip.ParseAddr(text)
		if err != nil {
			return nil, fmt.Errorf("invalid IP address %q", text)
		}
		n.addr = netip.PrefixFrom(addr, addr.BitLen())
		return n, nil
	case isStringField(field):
		if op != "contains" && op != "matches" && op != "==" && op != "!=" {
			return nil, fmt.Errorf("operator %q is not valid for %s", op, field)
		}
		return n, nil
	case isBytesField(field):
		if op != "contains" && op != "matches" {
			return nil, fmt.Errorf("operator %q is not valid for %s (try contains)", op, field)
		}
		return n, nil
	default:
		if op == "contains" || op == "matches" {
			return nil, fmt.Errorf("operator %q is only valid for string fields", op)
		}
		var val uint64
		var err error
		if v.kind == tokNumber {
			val = v.num
		} else {
			val, err = parseFieldValue(field, text)
			if err != nil {
				return nil, err
			}
		}
		n.num = val
		return n, nil
	}
}

func parseFieldValue(field, text string) (uint64, error) {
	switch field {
	case "ip.proto", "ip.protocol":
		switch strings.ToLower(text) {
		case "icmp":
			return 1, nil
		case "tcp":
			return 6, nil
		case "udp":
			return 17, nil
		case "icmpv6", "icmp6":
			return 58, nil
		}
	case "eth.type":
		switch strings.ToLower(text) {
		case "ip", "ipv4":
			return 0x0800, nil
		case "ipv6":
			return 0x86dd, nil
		case "arp":
			return 0x0806, nil
		}
	}
	n, err := strconv.ParseUint(text, 0, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid value %q for %s", text, field)
	}
	return n, nil
}

func isAddrField(f string) bool {
	switch f {
	case "ip.src", "ip.dst", "ip.addr", "ipv6.src", "ipv6.dst", "ipv6.addr",
		"ip6.src", "ip6.dst", "ip6.addr", "arp.src.proto_ipv4", "arp.dst.proto_ipv4":
		return true
	}
	return false
}

func isBytesField(f string) bool {
	switch f {
	case "frame", "tcp", "udp", "data", "payload", "http", "dns", "tls",
		"ntp", "snmp", "syslog", "stun", "mqtt", "redis", "postgresql",
		"bgp", "ssh", "ssdp", "sip", "quic", "http2", "vxlan", "mpls",
		"gre", "igmp", "wireguard":
		return true
	}
	return false
}

func isStringField(f string) bool {
	switch f {
	case "eth.src", "eth.dst", "dns.qry.name", "http.request.method", "http.request.uri",
		"http.host", "http.request.full_uri", "tls.handshake.extensions_server_name",
		"tls.handshake.extensions.server_name", "frame.protocols":
		return true
	}
	return false
}

// knownFields lists every field accepted by the parser.
var knownFields = map[string]bool{
	"frame.len": true, "frame.cap_len": true, "frame.number": true, "frame.protocols": true,
	"vlan.id": true, "eth.src": true, "eth.dst": true, "eth.type": true,
	"ip.version": true, "ip.proto": true, "ip.protocol": true, "ip.ttl": true, "ip.len": true,
	"ip.src": true, "ip.dst": true, "ip.addr": true,
	"ipv6.src": true, "ipv6.dst": true, "ipv6.addr": true, "ipv6.hlim": true,
	"ip6.src": true, "ip6.dst": true, "ip6.addr": true,
	"tcp.srcport": true, "tcp.dstport": true, "tcp.port": true, "tcp.flags": true,
	"tcp.flags.syn": true, "tcp.flags.ack": true, "tcp.flags.fin": true, "tcp.flags.reset": true,
	"tcp.flags.rst": true, "tcp.flags.push": true, "tcp.flags.psh": true, "tcp.flags.urg": true,
	"tcp.flags.ece": true, "tcp.flags.cwr": true,
	"tcp.seq": true, "tcp.ack": true, "tcp.window": true, "tcp.window_size_value": true,
	"tcp.len": true, "tcp.payload.len": true,
	"udp.srcport": true, "udp.dstport": true, "udp.port": true, "udp.length": true,
	"icmp.type": true, "icmp.code": true, "icmpv6.type": true,
	"arp.opcode": true, "arp.src.proto_ipv4": true, "arp.dst.proto_ipv4": true,
	"dns.id": true, "dns.flags.response": true, "dns.qry.name": true, "dns.qry.name.raw": true,
	"http.request.method": true, "http.request.uri": true, "http.host": true,
	"http.request.full_uri": true, "http.response.code": true,
	"tls.handshake.type": true, "tls.handshake.extensions_server_name": true,
	"tls.handshake.extensions.server_name": true,
	"protocol":                             true, "frame.protocol": true,
	"frame": true, "tcp": true, "udp": true, "data": true, "payload": true,
	"http": true, "dns": true, "tls": true,
}

// IsValidField reports whether name is a recognised field or protocol.
func IsValidField(name string) bool {
	return knownFields[strings.ToLower(name)] || isProtoName(strings.ToLower(name))
}

// KnownFields returns the sorted list of field names for autocompletion.
func KnownFields() []string {
	out := make([]string, 0, len(knownFields))
	for f := range knownFields {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}
