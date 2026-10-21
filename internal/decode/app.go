package decode

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------- dispatchers

var httpPorts = map[uint16]bool{80: true, 81: true, 591: true, 3000: true, 3128: true, 8000: true, 8008: true, 8080: true, 8081: true, 8888: true}
var tlsPorts = map[uint16]bool{443: true, 465: true, 636: true, 853: true, 993: true, 995: true, 8443: true, 9443: true, 10443: true}
var dnsPorts = map[uint16]bool{53: true, 5353: true, 5355: true}

func (c *ctx) dissectUDPPayload(b []byte, base int, sport, dport uint16) bool {
	if len(b) == 0 {
		return true
	}
	if dnsPorts[sport] || dnsPorts[dport] {
		if c.dissectDNS(b, base, false) {
			return true
		}
	}
	if isDHCP(sport, dport) {
		if c.dissectDHCP(b, base) {
			return true
		}
	}
	switch {
	case sport == 123 || dport == 123:
		return c.dissectNTP(b, base)
	case sport == 161 || dport == 161 || sport == 162 || dport == 162:
		return c.dissectSNMP(b, base)
	case sport == 514 || dport == 514:
		return c.dissectSyslog(b, base)
	case sport == 3478 || dport == 3478 || sport == 3479 || dport == 3479:
		return c.dissectSTUN(b, base)
	case sport == 4789 || dport == 4789 || sport == 8472 || dport == 8472:
		return c.dissectVXLAN(b, base)
	case sport == 51820 || dport == 51820:
		return c.dissectWireGuard(b, base)
	case sport == 1900 || dport == 1900:
		return c.dissectSSDP(b, base)
	case sport == 5060 || dport == 5060:
		return c.dissectSIP(b, base)
	case (sport == 443 || dport == 443) && looksLikeQUIC(b):
		return c.dissectQUIC(b, base)
	}
	return false
}

func (c *ctx) dissectTCPPayload(b []byte, base int, sport, dport uint16) {
	if len(b) == 0 {
		return
	}
	if dnsPorts[sport] || dnsPorts[dport] {
		if c.dissectDNS(b, base, true) {
			return
		}
	}
	if looksLikeHTTP2(b) && c.dissectHTTP2(b, base) {
		return
	}
	if looksLikeSSHBanner(b) && c.dissectSSH(b, base) {
		return
	}
	switch {
	case sport == 6379 || dport == 6379:
		if c.dissectRedis(b, base) {
			return
		}
	case sport == 5432 || dport == 5432:
		if c.dissectPostgreSQL(b, base) {
			return
		}
	case sport == 1883 || dport == 1883:
		if c.dissectMQTT(b, base) {
			return
		}
	case sport == 179 || dport == 179:
		if c.dissectBGP(b, base) {
			return
		}
	case sport == 22 || dport == 22:
		if c.dissectSSH(b, base) {
			return
		}
	case sport == 5060 || dport == 5060:
		if c.dissectSIP(b, base) {
			return
		}
	case sport == 514 || dport == 514:
		if c.dissectSyslog(b, base) {
			return
		}
	}
	if httpPorts[sport] || httpPorts[dport] || looksLikeHTTP(b) {
		if c.dissectHTTP(b, base) {
			return
		}
	}
	if tlsPorts[sport] || tlsPorts[dport] || looksLikeTLS(b) {
		if c.dissectTLS(b, base) {
			return
		}
	}
	c.addLayer("data")
	c.addRoot(newField(fmt.Sprintf("TCP payload (%d bytes)", len(b)), hexPreview(b, 64), base, len(b)))
}

// ---------------------------------------------------------------------- DNS

func (c *ctx) dissectDNS(msg []byte, base int, tcp bool) bool {
	data := msg
	dnsBase := base
	if tcp {
		if len(msg) < 2 {
			return false
		}
		l := int(be16(msg[0:2]))
		if l < 12 || len(msg) < 2+l {
			return false
		}
		data = msg[2 : 2+l]
		dnsBase = base + 2
	}
	if len(data) < 12 {
		return false
	}
	id := be16(data[0:2])
	flags := be16(data[2:4])
	qd := int(be16(data[4:6]))
	an := int(be16(data[6:8]))
	ns := int(be16(data[8:10]))
	ar := int(be16(data[10:12]))
	if qd > 64 || an > 256 {
		return false
	}

	qr := flags&0x8000 != 0
	opcode := (flags >> 11) & 0xf
	rcode := flags & 0xf

	c.addLayer("dns")
	c.proto = "dns"
	c.m.DNSID = id
	c.m.DNSResponse = qr

	root := newNode(fmt.Sprintf("Domain Name System (%s)", dnsOpcodeName(opcode, qr)), dnsBase, len(data))
	flagNode := newField(fmt.Sprintf("Flags: 0x%04x", flags), "", dnsBase+2, 2)
	flagNode.add(
		newField(fmt.Sprintf("Response: %d", boolInt(qr)), "", dnsBase+2, 1),
		newField(fmt.Sprintf("Opcode: %s (%d)", dnsOpcodeName(opcode, false), opcode), "", dnsBase+2, 1),
		newField(fmt.Sprintf("Authoritative: %d", boolInt(flags&0x0400 != 0)), "", dnsBase+2, 1),
		newField(fmt.Sprintf("Truncated: %d", boolInt(flags&0x0200 != 0)), "", dnsBase+2, 1),
		newField(fmt.Sprintf("Recursion desired: %d", boolInt(flags&0x0100 != 0)), "", dnsBase+2, 1),
		newField(fmt.Sprintf("Recursion available: %d", boolInt(flags&0x0080 != 0)), "", dnsBase+3, 1),
		newField(fmt.Sprintf("Reply code: %s (%d)", dnsRcodeName(rcode), rcode), "", dnsBase+3, 1),
	)
	root.add(
		newField(fmt.Sprintf("Transaction ID: 0x%04x", id), "", dnsBase, 2),
		flagNode,
		newField(fmt.Sprintf("Questions: %d", qd), "", dnsBase+4, 2),
		newField(fmt.Sprintf("Answer RRs: %d", an), "", dnsBase+6, 2),
		newField(fmt.Sprintf("Authority RRs: %d", ns), "", dnsBase+8, 2),
		newField(fmt.Sprintf("Additional RRs: %d", ar), "", dnsBase+10, 2),
	)

	off := 12
	var qNames []string
	var qTypes []uint16
	for i := 0; i < qd; i++ {
		name, next, ok := dnsReadName(data, off, 0)
		if !ok || next+4 > len(data) {
			break
		}
		qtype := be16(data[next : next+2])
		qclass := be16(data[next+2 : next+4])
		qNames = append(qNames, name)
		qTypes = append(qTypes, qtype)
		q := newField(fmt.Sprintf("Queries: %s: type %s, class %s", name, dnsTypeName(qtype), dnsClassName(qclass)), "", dnsBase+off, next+4-off)
		q.add(
			newField("Name: "+name, "", dnsBase+off, next-off),
			newField(fmt.Sprintf("Type: %s (%d)", dnsTypeName(qtype), qtype), "", dnsBase+next, 2),
			newField(fmt.Sprintf("Class: %s (0x%04x)", dnsClassName(qclass), qclass), "", dnsBase+next+2, 2),
		)
		root.add(q)
		off = next + 4
	}

	rr := newField("Answers", "", 0, 0)
	var answers []string
	for i := 0; i < an && off < len(data); i++ {
		name, next, ok := dnsReadName(data, off, 0)
		if !ok || next+10 > len(data) {
			break
		}
		rtype := be16(data[next : next+2])
		rclass := be16(data[next+2 : next+4])
		ttl := be32(data[next+4 : next+8])
		rdlen := int(be16(data[next+8 : next+10]))
		if next+10+rdlen > len(data) {
			break
		}
		rdata := data[next+10 : next+10+rdlen]
		val := dnsRDataString(data, rtype, rdata, next+10)
		f := newField(fmt.Sprintf("%s: type %s, class %s, ttl %d, %s", name, dnsTypeName(rtype), dnsClassName(rclass), ttl, val), "", dnsBase+off, next+10+rdlen-off)
		f.add(
			newField("Name: "+name, "", dnsBase+off, next-off),
			newField(fmt.Sprintf("Type: %s (%d)", dnsTypeName(rtype), rtype), "", dnsBase+next, 2),
			newField(fmt.Sprintf("Class: %s", dnsClassName(rclass)), "", dnsBase+next+2, 2),
			newField(fmt.Sprintf("Time to live: %d (seconds)", ttl), "", dnsBase+next+4, 4),
			newField(fmt.Sprintf("Data length: %d", rdlen), "", dnsBase+next+8, 2),
			newField(dnsTypeName(rtype)+": "+val, "", dnsBase+next+10, rdlen),
		)
		rr.add(f)
		answers = append(answers, dnsTypeName(rtype)+" "+val)
		off = next + 10 + rdlen
	}
	if len(rr.Children) > 0 {
		root.add(rr)
	}
	c.addRoot(root)

	name := ""
	qtype := uint16(0)
	if len(qNames) > 0 {
		name = qNames[0]
		qtype = qTypes[0]
		c.m.DNSName = name
	}
	if name == "" {
		name = fmt.Sprintf("0x%04x", id)
	}
	if qr {
		c.appInfo = fmt.Sprintf("Standard query response 0x%04x %s %s", id, dnsTypeName(qtype), name)
		if rcode != 0 {
			c.appInfo += " " + dnsRcodeName(rcode)
		}
		if len(answers) > 0 {
			summary := strings.Join(answers, ", ")
			if len(summary) > 96 {
				summary = summary[:93] + "…"
			}
			c.appInfo += " " + summary
		}
	} else {
		c.appInfo = fmt.Sprintf("Standard query 0x%04x %s %s", id, dnsTypeName(qtype), name)
	}
	return true
}

func dnsReadName(msg []byte, off int, depth int) (string, int, bool) {
	if depth > 12 || off < 0 || off >= len(msg) {
		return "", off, false
	}
	var labels []string
	next := off
	jumped := false
	pos := off
	for i := 0; i < 128; i++ {
		if pos >= len(msg) {
			return "", off, false
		}
		l := int(msg[pos])
		if l == 0 {
			pos++
			if !jumped {
				next = pos
			}
			return strings.Join(labels, "."), next, true
		}
		if l&0xc0 == 0xc0 {
			if pos+1 >= len(msg) {
				return "", off, false
			}
			ptr := int(be16(msg[pos:pos+2]) & 0x3fff)
			if !jumped {
				next = pos + 2
				jumped = true
			}
			pos = ptr
			continue
		}
		if pos+1+l > len(msg) {
			return "", off, false
		}
		labels = append(labels, strings.ToLower(string(msg[pos+1:pos+1+l])))
		pos += 1 + l
		if !jumped {
			next = pos
		}
	}
	return "", off, false
}

func dnsRDataString(msg []byte, rtype uint16, rdata []byte, off int) string {
	switch rtype {
	case 1:
		if len(rdata) == 4 {
			return netip.AddrFrom4([4]byte{rdata[0], rdata[1], rdata[2], rdata[3]}).String()
		}
	case 28:
		if len(rdata) == 16 {
			var a [16]byte
			copy(a[:], rdata)
			return netip.AddrFrom16(a).String()
		}
	case 2, 5, 12, 15, 39:
		if n, _, ok := dnsReadName(msg, off, 0); ok {
			if rtype == 15 && len(rdata) > 2 {
				if n2, _, ok2 := dnsReadName(msg, off+2, 0); ok2 {
					return fmt.Sprintf("%d %s", be16(rdata), n2)
				}
			}
			return n
		}
	case 6:
		if n, next, ok := dnsReadName(msg, off, 0); ok {
			if n2, next2, ok2 := dnsReadName(msg, next, 0); ok2 && next2+4 <= len(msg) {
				return n + " " + n2 + fmt.Sprintf(" serial %d", be32(msg[next2:]))
			}
		}
	case 16:
		if len(rdata) > 1 {
			l := int(rdata[0])
			if l+1 <= len(rdata) {
				return string(rdata[1 : 1+l])
			}
		}
	}
	if len(rdata) == 0 {
		return "-"
	}
	return hexPreview(rdata, 24)
}

func dnsOpcodeName(op uint16, response bool) string {
	if response {
		return "Standard query response"
	}
	switch op {
	case 0:
		return "Standard query"
	case 1:
		return "Inverse query"
	case 2:
		return "Server status request"
	}
	return fmt.Sprintf("Opcode %d", op)
}

func dnsRcodeName(rc uint16) string {
	switch rc {
	case 0:
		return "No error"
	case 1:
		return "Format error"
	case 2:
		return "Server failure"
	case 3:
		return "Non-existent domain"
	case 4:
		return "Not implemented"
	case 5:
		return "Query refused"
	}
	return "Unknown"
}

func dnsTypeName(t uint16) string {
	switch t {
	case 1:
		return "A"
	case 2:
		return "NS"
	case 5:
		return "CNAME"
	case 6:
		return "SOA"
	case 12:
		return "PTR"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 28:
		return "AAAA"
	case 33:
		return "SRV"
	case 41:
		return "OPT"
	case 43:
		return "DS"
	case 46:
		return "RRSIG"
	case 47:
		return "NSEC"
	case 65:
		return "HTTPS"
	case 255:
		return "ANY"
	}
	return fmt.Sprintf("TYPE%d", t)
}

func dnsClassName(c uint16) string {
	switch c {
	case 1:
		return "IN"
	case 3:
		return "CH"
	case 4:
		return "HS"
	case 255:
		return "ANY"
	}
	return fmt.Sprintf("CLASS%d", c)
}

// --------------------------------------------------------------------- HTTP

func looksLikeHTTP(b []byte) bool {
	s := string(b)
	nl := strings.IndexAny(s, "\r\n")
	if nl < 0 {
		// A very short segment may contain only part of the start line.
		nl = len(s)
	}
	line := strings.TrimRight(s[:nl], "\r")
	if strings.HasPrefix(line, "HTTP/1.") || strings.HasPrefix(line, "HTTP/2") {
		return true
	}
	parts := strings.Split(line, " ")
	if len(parts) < 3 || !isHTTPMethod(parts[0]) {
		return false
	}
	ver := parts[len(parts)-1]
	return strings.HasPrefix(ver, "HTTP/1.") || strings.HasPrefix(ver, "HTTP/2")
}

func isHTTPMethod(m string) bool {
	switch m {
	case "GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH", "CONNECT", "TRACE":
		return true
	}
	return false
}

func (c *ctx) dissectHTTP(b []byte, base int) bool {
	nl := strings.Index(string(b), "\r\n")
	if nl < 0 {
		nl = strings.Index(string(b), "\n")
	}
	if nl <= 0 {
		return false
	}
	firstLine := string(b[:nl])
	parts := strings.Fields(firstLine)
	if len(parts) < 2 {
		return false
	}
	isRequest := false
	switch {
	case isHTTPMethod(parts[0]):
		if len(parts) < 3 || !strings.HasPrefix(parts[len(parts)-1], "HTTP/") {
			return false
		}
		isRequest = true
	case strings.HasPrefix(parts[0], "HTTP/1.") || strings.HasPrefix(parts[0], "HTTP/2"):
		if len(parts) < 2 {
			return false
		}
	default:
		return false
	}

	c.addLayer("http")
	c.proto = "http"
	headerEnd := len(b)
	for i := 0; i+1 < len(b); i++ {
		if b[i] == '\n' && b[i+1] == '\n' {
			headerEnd = i + 2
			break
		}
		if b[i] == '\n' && i+2 < len(b) && b[i+1] == '\r' && b[i+2] == '\n' {
			headerEnd = i + 3
			break
		}
	}

	root := newNode("Hypertext Transfer Protocol", base, headerEnd)
	headers := map[string]string{}
	var headerOrder []string
	off := nl + 1
	for off < headerEnd {
		next := strings.Index(string(b[off:headerEnd]), "\n")
		if next < 0 {
			next = headerEnd - off
		}
		line := strings.TrimRight(string(b[off:off+next]), "\r")
		if line == "" {
			off += next + 1
			continue
		}
		if idx := strings.Index(line, ":"); idx > 0 {
			k := strings.ToLower(strings.TrimSpace(line[:idx]))
			v := strings.TrimSpace(line[idx+1:])
			if _, ok := headers[k]; !ok {
				headerOrder = append(headerOrder, k)
			}
			headers[k] = v
			root.add(newField(fmt.Sprintf("%s: %s", canonicalHeader(k), v), "", base+off, next))
		}
		off += next + 1
	}

	body := b[headerEnd:]
	if len(body) > 0 {
		root.add(newField(fmt.Sprintf("Body (%d bytes)", len(body)), hexPreview(body, 32), base+headerEnd, len(body)))
	}

	if isRequest {
		method, uri, version := parts[0], parts[1], ""
		if len(parts) >= 3 {
			version = parts[2]
		}
		c.m.HTTPMethod = method
		c.m.HTTPURI = uri
		c.m.HTTPHost = headers["host"]
		root.add(
			newField("Request Method: "+method, "", base, len(parts[0])),
			newField("Request URI: "+uri, "", base+len(parts[0])+1, len(parts[1])),
		)
		if version != "" {
			root.add(newField("Request Version: "+version, "", base, 0))
		}
		c.appInfo = fmt.Sprintf("%s %s", method, uri)
		if v := headers["host"]; v != "" {
			c.appInfo += " (Host: " + v + ")"
		}
		if v := headers["content-type"]; v != "" && len(body) > 0 {
			c.appInfo += fmt.Sprintf(" [%s; %d bytes]", v, len(body))
		}
	} else {
		code := 0
		if len(parts) >= 2 {
			if v, err := strconv.Atoi(parts[1]); err == nil {
				code = v
			}
		}
		c.m.HTTPCode = code
		root.add(
			newField("Response Version: "+parts[0], "", base, len(parts[0])),
			newField(fmt.Sprintf("Status Code: %d", code), "", base+len(parts[0])+1, len(parts[1])),
		)
		c.appInfo = fmt.Sprintf("%s %s", parts[1], strings.Join(parts[2:], " "))
		if v := headers["content-type"]; v != "" && len(body) > 0 {
			c.appInfo += fmt.Sprintf(" [%s; %d bytes]", v, len(body))
		}
	}

	// Prepend a line field for the start line (offset points at the line).
	root.Children = append([]*Field{newField(firstLine, "", base, nl)}, root.Children...)
	c.addRoot(root)
	return true
}

func canonicalHeader(k string) string {
	parts := strings.Split(k, "-")
	for i, p := range parts {
		if p == "" {
			continue
		}
		parts[i] = strings.ToUpper(p[:1]) + p[1:]
	}
	return strings.Join(parts, "-")
}

// ---------------------------------------------------------------------- TLS

func looksLikeTLS(b []byte) bool {
	if len(b) < 5 {
		return false
	}
	if b[0] < 20 || b[0] > 24 {
		return false
	}
	if b[1] != 3 || b[2] > 4 {
		return false
	}
	l := int(be16(b[3:5]))
	return l > 0 && l <= 16384+2048
}

func tlsVersionName(v uint16) string {
	switch v {
	case 0x0300:
		return "SSL 3.0"
	case 0x0301:
		return "TLS 1.0"
	case 0x0302:
		return "TLS 1.1"
	case 0x0303:
		return "TLS 1.2"
	case 0x0304:
		return "TLS 1.3"
	}
	return fmt.Sprintf("0x%04x", v)
}

func tlsContentTypeName(t uint8) string {
	switch t {
	case 20:
		return "Change Cipher Spec"
	case 21:
		return "Alert"
	case 22:
		return "Handshake"
	case 23:
		return "Application Data"
	case 24:
		return "Heartbeat"
	}
	return fmt.Sprintf("Content Type %d", t)
}

func tlsHandshakeName(t uint8) string {
	switch t {
	case 0:
		return "Hello Request"
	case 1:
		return "Client Hello"
	case 2:
		return "Server Hello"
	case 4:
		return "New Session Ticket"
	case 8:
		return "Encrypted Extensions"
	case 11:
		return "Certificate"
	case 12:
		return "Server Key Exchange"
	case 13:
		return "Certificate Request"
	case 14:
		return "Server Hello Done"
	case 15:
		return "Certificate Verify"
	case 16:
		return "Client Key Exchange"
	case 20:
		return "Finished"
	}
	return fmt.Sprintf("Handshake Type %d", t)
}

func (c *ctx) dissectTLS(b []byte, base int) bool {
	if len(b) < 5 {
		return false
	}
	ct := b[0]
	ver := be16(b[1:3])
	recLen := int(be16(b[3:5]))
	if recLen == 0 || 5+recLen > len(b) {
		recLen = len(b) - 5
	}
	c.addLayer("tls")
	c.proto = "tls"

	root := newNode(fmt.Sprintf("Transport Layer Security (%s)", tlsContentTypeName(ct)), base, 5+recLen)
	root.add(
		newField(fmt.Sprintf("Content Type: %s (%d)", tlsContentTypeName(ct), ct), "", base, 1),
		newField(fmt.Sprintf("Version: %s (0x%04x)", tlsVersionName(ver), ver), "", base+1, 2),
		newField(fmt.Sprintf("Length: %d", recLen), "", base+3, 2),
	)

	body := b[5 : 5+recLen]
	c.m.Payload = body
	c.appInfo = tlsContentTypeName(ct)

	if ct == 22 && len(body) >= 4 {
		ht := body[0]
		hl := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
		c.m.TLSHandshake = ht
		hsNode := newNode(fmt.Sprintf("%s (length %d)", tlsHandshakeName(ht), hl), base+5, min(hl+4, len(body)))
		end := 4 + hl
		if end > len(body) {
			end = len(body)
		}
		switch ht {
		case 1:
			c.parseClientHello(body[4:end], base+9, hsNode)
		case 2:
			c.parseServerHello(body[4:end], base+9, hsNode)
		case 11:
			if len(body) >= 7 {
				certLen := int(body[4])<<16 | int(body[5])<<8 | int(body[6])
				hsNode.add(newField(fmt.Sprintf("Certificates Length: %d", certLen), "", base+9, 3))
			}
		}
		root.add(hsNode)
		c.appInfo = tlsHandshakeName(ht)
		if c.m.TLSSNI != "" {
			c.appInfo += " (SNI=" + c.m.TLSSNI + ")"
		}
	} else if ct == 23 {
		if len(body) > 0 {
			root.add(newField(fmt.Sprintf("Application Data (%d bytes)", len(body)), hexPreview(body, 32), base+5, len(body)))
		}
		c.appInfo = fmt.Sprintf("Application Data (%d bytes)", len(body))
	} else if ct == 21 && len(body) >= 2 {
		root.add(newField(fmt.Sprintf("Alert Level: %d, Description: %d", body[0], body[1]), "", base+5, 2))
		c.appInfo = fmt.Sprintf("Alert (level %d, description %d)", body[0], body[1])
	}

	c.addRoot(root)
	return true
}

func (c *ctx) parseClientHello(b []byte, base int, node *Field) {
	if len(b) < 34 {
		return
	}
	ver := be16(b[0:2])
	node.add(newField(fmt.Sprintf("Version: %s (0x%04x)", tlsVersionName(ver), ver), "", base, 2))

	off := 34
	if off >= len(b) {
		return
	}
	sidLen := int(b[off])
	off += 1 + sidLen
	if off+2 > len(b) {
		return
	}
	csLen := int(be16(b[off : off+2]))
	off += 2 + csLen
	if off >= len(b) {
		return
	}
	compLen := int(b[off])
	off += 1 + compLen
	if off+2 > len(b) {
		return
	}
	extTotal := int(be16(b[off : off+2]))
	off += 2
	end := off + extTotal
	if end > len(b) {
		end = len(b)
	}
	extNode := newField(fmt.Sprintf("Extensions (%d bytes)", extTotal), "", base+off, end-off)
	for off+4 <= end {
		etype := be16(b[off : off+2])
		elen := int(be16(b[off+2 : off+4]))
		if off+4+elen > end {
			break
		}
		edata := b[off+4 : off+4+elen]
		name := tlsExtensionName(etype)
		f := newField(fmt.Sprintf("%s (%d bytes)", name, elen), "", base+off, 4+elen)
		if etype == 0 && len(edata) >= 5 {
			// server_name extension: list length, type, name length, name
			listLen := int(be16(edata[0:2]))
			p := 2
			for p+3 <= len(edata) && p < 2+listLen {
				ntype := edata[p]
				nlen := int(be16(edata[p+1 : p+3]))
				if p+3+nlen > len(edata) {
					break
				}
				if ntype == 0 {
					sni := string(edata[p+3 : p+3+nlen])
					c.m.TLSSNI = sni
					f.add(newField("Server Name: "+sni, "", base+off+4+p+3, nlen))
				}
				p += 3 + nlen
			}
		}
		if etype == 16 && len(edata) >= 5 {
			p := 0
			for p+4 <= len(edata) {
				gname := be16(edata[p : p+2])
				glen := int(be16(edata[p+2 : p+4]))
				if p+4+glen > len(edata) {
					break
				}
				if gname == 0 {
					groups := []string{}
					for q := p + 4; q+2 <= p+4+glen; q += 2 {
						groups = append(groups, tlsGroupName(be16(edata[q:q+2])))
					}
					f.add(newField("Supported Groups: "+strings.Join(groups, ", "), "", base+off+4+p, glen+4))
					break
				}
				p += 4 + glen
			}
		}
		extNode.add(f)
		off += 4 + elen
	}
	if len(extNode.Children) > 0 {
		node.add(extNode)
	}
}

func (c *ctx) parseServerHello(b []byte, base int, node *Field) {
	if len(b) < 34 {
		return
	}
	ver := be16(b[0:2])
	node.add(newField(fmt.Sprintf("Version: %s (0x%04x)", tlsVersionName(ver), ver), "", base, 2))
}

func tlsExtensionName(t uint16) string {
	switch t {
	case 0:
		return "server_name"
	case 5:
		return "status_request"
	case 10:
		return "supported_groups"
	case 11:
		return "ec_point_formats"
	case 13:
		return "signature_algorithms"
	case 16:
		return "application_layer_protocol_negotiation"
	case 18:
		return "signed_certificate_timestamp"
	case 21:
		return "padding"
	case 23:
		return "extended_master_secret"
	case 27:
		return "compress_certificate"
	case 35:
		return "session_ticket"
	case 41:
		return "pre_shared_key"
	case 43:
		return "supported_versions"
	case 45:
		return "psk_key_exchange_modes"
	case 51:
		return "key_share"
	}
	return fmt.Sprintf("extension %d", t)
}

func tlsGroupName(g uint16) string {
	switch g {
	case 23:
		return "secp256r1"
	case 24:
		return "secp384r1"
	case 25:
		return "secp521r1"
	case 29:
		return "x25519"
	case 256:
		return "ffdhe2048"
	case 257:
		return "ffdhe3072"
	}
	return fmt.Sprintf("0x%04x", g)
}

// ---------------------------------------------------------------- DHCP

func isDHCP(sport, dport uint16) bool {
	return (sport == 67 && dport == 68) || (sport == 68 && dport == 67)
}

func (c *ctx) dissectDHCP(b []byte, base int) bool {
	if len(b) < 240 {
		return false
	}
	if b[0] != 1 && b[0] != 2 {
		return false
	}
	msgType := uint8(0)
	var hostname, requestedIP string
	for off := 240; off < len(b); {
		opt := b[off]
		if opt == 255 {
			break
		}
		if opt == 0 {
			off++
			continue
		}
		if off+1 >= len(b) {
			break
		}
		l := int(b[off+1])
		if off+2+l > len(b) {
			break
		}
		v := b[off+2 : off+2+l]
		switch opt {
		case 53:
			if l >= 1 {
				msgType = v[0]
			}
		case 12:
			hostname = string(v)
		case 50:
			if l == 4 {
				requestedIP = netip.AddrFrom4([4]byte{v[0], v[1], v[2], v[3]}).String()
			}
		}
		off += 2 + l
	}

	c.addLayer("dhcp")
	c.proto = "dhcp"
	root := newNode(fmt.Sprintf("Dynamic Host Configuration Protocol (%s)", dhcpTypeName(msgType)), base, len(b))
	root.add(
		newField(fmt.Sprintf("Message type: %s (%d)", dhcpTypeName(msgType), msgType), "", base, 1),
		newField("Hardware type: "+arpHwName(be16(b[1:3])), "", base+1, 1),
		newField(fmt.Sprintf("Hardware address length: %d", b[2]), "", base+2, 1),
		newField(fmt.Sprintf("Transaction ID: 0x%08x", be32(b[4:8])), "", base+4, 4),
		newField(fmt.Sprintf("Client IP address: %s", ip4String(be32(b[12:16]))), "", base+12, 4),
		newField(fmt.Sprintf("Your (client) IP address: %s", ip4String(be32(b[16:20]))), "", base+16, 4),
		newField(fmt.Sprintf("Next server IP address: %s", ip4String(be32(b[20:24]))), "", base+20, 4),
		newField(fmt.Sprintf("Client MAC address: %s", macString(b[28:34])), "", base+28, 6),
	)
	if hostname != "" {
		root.add(newField("Host Name: "+hostname, "", 0, 0))
	}
	if requestedIP != "" {
		root.add(newField("Requested IP Address: "+requestedIP, "", 0, 0))
	}
	c.addRoot(root)

	c.appInfo = dhcpTypeName(msgType)
	if hostname != "" {
		c.appInfo += " (" + hostname + ")"
	}
	return true
}

func dhcpTypeName(t uint8) string {
	switch t {
	case 1:
		return "DHCP Discover"
	case 2:
		return "DHCP Offer"
	case 3:
		return "DHCP Request"
	case 4:
		return "DHCP Decline"
	case 5:
		return "DHCP ACK"
	case 6:
		return "DHCP NAK"
	case 7:
		return "DHCP Release"
	case 8:
		return "DHCP Inform"
	}
	return "DHCP"
}
