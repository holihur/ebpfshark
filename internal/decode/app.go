package decode

import (
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"sync"
)

// ---------------------------------------------------------------- dispatchers

var httpPorts = map[uint16]bool{80: true, 81: true, 591: true, 3000: true, 3128: true, 8000: true, 8008: true, 8080: true, 8081: true, 8888: true}
var tlsPorts = map[uint16]bool{443: true, 465: true, 636: true, 853: true, 993: true, 995: true, 8443: true, 9443: true, 10443: true}
var dnsPorts = map[uint16]bool{53: true, 5353: true, 5355: true}

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

	root := c.newNode(fmt.Sprintf("Domain Name System (%s)", dnsOpcodeName(opcode, qr)), dnsBase, len(data))
	flagNode := c.newField(fmt.Sprintf("Flags: 0x%04x", flags), "", dnsBase+2, 2)
	flagNode.add(
		c.newField(fmt.Sprintf("Response: %d", boolInt(qr)), "", dnsBase+2, 1),
		c.newField(fmt.Sprintf("Opcode: %s (%d)", dnsOpcodeName(opcode, false), opcode), "", dnsBase+2, 1),
		c.newField(fmt.Sprintf("Authoritative: %d", boolInt(flags&0x0400 != 0)), "", dnsBase+2, 1),
		c.newField(fmt.Sprintf("Truncated: %d", boolInt(flags&0x0200 != 0)), "", dnsBase+2, 1),
		c.newField(fmt.Sprintf("Recursion desired: %d", boolInt(flags&0x0100 != 0)), "", dnsBase+2, 1),
		c.newField(fmt.Sprintf("Recursion available: %d", boolInt(flags&0x0080 != 0)), "", dnsBase+3, 1),
		c.newField(fmt.Sprintf("Authentic data: %d", boolInt(flags&0x0020 != 0)), "", dnsBase+3, 1),
		c.newField(fmt.Sprintf("Checking disabled: %d", boolInt(flags&0x0010 != 0)), "", dnsBase+3, 1),
		c.newField(fmt.Sprintf("Reply code: %s (%d)", dnsRcodeName(rcode), rcode), "", dnsBase+3, 1),
	)
	root.add(
		c.newField(fmt.Sprintf("Transaction ID: 0x%04x", id), "", dnsBase, 2),
		flagNode,
		c.newField(fmt.Sprintf("Questions: %d", qd), "", dnsBase+4, 2),
		c.newField(fmt.Sprintf("Answer RRs: %d", an), "", dnsBase+6, 2),
		c.newField(fmt.Sprintf("Authority RRs: %d", ns), "", dnsBase+8, 2),
		c.newField(fmt.Sprintf("Additional RRs: %d", ar), "", dnsBase+10, 2),
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
		q := c.newField(fmt.Sprintf("Queries: %s: type %s, class %s", name, dnsTypeName(qtype), dnsClassName(qclass)), "", dnsBase+off, next+4-off)
		q.add(
			c.newField("Name: "+name, "", dnsBase+off, next-off),
			c.newField(fmt.Sprintf("Type: %s (%d)", dnsTypeName(qtype), qtype), "", dnsBase+next, 2),
			c.newField(fmt.Sprintf("Class: %s (0x%04x)", dnsClassName(qclass), qclass), "", dnsBase+next+2, 2),
		)
		root.add(q)
		off = next + 4
	}

	rr := c.newField("Answers", "", 0, 0)
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
		f := c.newField(fmt.Sprintf("%s: type %s, class %s, ttl %d, %s", name, dnsTypeName(rtype), dnsClassName(rclass), ttl, val), "", dnsBase+off, next+10+rdlen-off)
		f.add(
			c.newField("Name: "+name, "", dnsBase+off, next-off),
			c.newField(fmt.Sprintf("Type: %s (%d)", dnsTypeName(rtype), rtype), "", dnsBase+next, 2),
			c.newField(fmt.Sprintf("Class: %s", dnsClassName(rclass)), "", dnsBase+next+2, 2),
			c.newField(fmt.Sprintf("Time to live: %d (seconds)", ttl), "", dnsBase+next+4, 4),
			c.newField(fmt.Sprintf("Data length: %d", rdlen), "", dnsBase+next+8, 2),
			c.newField(dnsTypeName(rtype)+": "+val, "", dnsBase+next+10, rdlen),
		)
		if rtype == 41 { // EDNS0 OPT pseudo-record
			extRcode := uint16((ttl >> 24) & 0xff)
			version := (ttl >> 16) & 0xff
			do := ttl&0x8000 != 0
			f.Label = fmt.Sprintf("OPT (EDNS0): UDP payload %d, extended RCODE %d, version %d, DO %d", rclass, extRcode, version, boolInt(do))
			f.add(
				c.newField(fmt.Sprintf("UDP Payload Size: %d", rclass), "", dnsBase+next+2, 2),
				c.newField(fmt.Sprintf("Extended RCODE: %d", extRcode), "", dnsBase+next+4, 1),
				c.newField(fmt.Sprintf("EDNS Version: %d", version), "", dnsBase+next+5, 1),
				c.newField(fmt.Sprintf("DNSSEC OK: %d", boolInt(do)), "", dnsBase+next+6, 1),
			)
			for p := 0; p+4 <= len(rdata); {
				ocode := be16(rdata[p : p+2])
				olen := int(be16(rdata[p+2 : p+4]))
				if p+4+olen > len(rdata) {
					break
				}
				oval := rdata[p+4 : p+4+olen]
				oname := fmt.Sprintf("EDNS Option %d", ocode)
				switch ocode {
				case 8:
					oname = "Client Subnet"
				case 10:
					oname = "Cookie"
				case 12:
					oname = "Padding"
				case 15:
					oname = "Extended DNS Error"
				}
				f.add(c.newField(fmt.Sprintf("%s (%d bytes): %s", oname, olen, hexPreview(oval, 32)), "", dnsBase+next+10+p, 4+olen))
				p += 4 + olen
			}
		} else {
			answers = append(answers, dnsTypeName(rtype)+" "+val)
		}
		rr.add(f)
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
	case 33: // SRV
		if len(rdata) >= 6 {
			if n, _, ok := dnsReadName(msg, off+6, 0); ok {
				return fmt.Sprintf("priority %d weight %d port %d target %s", be16(rdata[0:2]), be16(rdata[2:4]), be16(rdata[4:6]), n)
			}
		}
	case 35: // NAPTR
		if len(rdata) >= 4 {
			p := 4
			readStr := func() string {
				if p >= len(rdata) {
					return ""
				}
				l := int(rdata[p])
				p++
				if p+l > len(rdata) {
					return ""
				}
				s := string(rdata[p : p+l])
				p += l
				return s
			}
			flags := readStr()
			service := readStr()
			regexp := readStr()
			repl, _, ok := dnsReadName(msg, off+p, 0)
			if ok {
				return fmt.Sprintf("order %d pref %d flags %q service %q regexp %q replacement %s", be16(rdata[0:2]), be16(rdata[2:4]), flags, service, regexp, repl)
			}
		}
	case 52: // TLSA
		if len(rdata) >= 3 {
			return fmt.Sprintf("usage %d selector %d matching %d %s", rdata[0], rdata[1], rdata[2], hexPreview(rdata[3:], 32))
		}
	case 64, 65: // SVCB / HTTPS
		if len(rdata) >= 3 {
			if n, _, ok := dnsReadName(msg, off+2, 0); ok {
				return fmt.Sprintf("priority %d target %s params %s", be16(rdata[0:2]), n, hexPreview(rdata[3:], 32))
			}
		}
	case 257: // CAA
		if len(rdata) >= 2 {
			l := int(rdata[1])
			if 2+l <= len(rdata) {
				return fmt.Sprintf("flags %d tag %s value %s", rdata[0], string(rdata[2:2+l]), string(rdata[2+l:]))
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
	case 35:
		return "NAPTR"
	case 41:
		return "OPT"
	case 43:
		return "DS"
	case 46:
		return "RRSIG"
	case 47:
		return "NSEC"
	case 52:
		return "TLSA"
	case 64:
		return "SVCB"
	case 65:
		return "HTTPS"
	case 255:
		return "ANY"
	case 256:
		return "URI"
	case 257:
		return "CAA"
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

	root := c.newNode("Hypertext Transfer Protocol", base, headerEnd)
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
			root.add(c.newField(fmt.Sprintf("%s: %s", canonicalHeader(k), v), "", base+off, next))
		}
		off += next + 1
	}

	body := b[headerEnd:]
	if len(body) > 0 {
		root.add(c.newField(fmt.Sprintf("Body (%d bytes)", len(body)), hexPreview(body, 32), base+headerEnd, len(body)))
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
			c.newField("Request Method: "+method, "", base, len(parts[0])),
			c.newField("Request URI: "+uri, "", base+len(parts[0])+1, len(parts[1])),
		)
		if version != "" {
			root.add(c.newField("Request Version: "+version, "", base, 0))
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
			c.newField("Response Version: "+parts[0], "", base, len(parts[0])),
			c.newField(fmt.Sprintf("Status Code: %d", code), "", base+len(parts[0])+1, len(parts[1])),
		)
		c.appInfo = fmt.Sprintf("%s %s", parts[1], strings.Join(parts[2:], " "))
		if v := headers["content-type"]; v != "" && len(body) > 0 {
			c.appInfo += fmt.Sprintf(" [%s; %d bytes]", v, len(body))
		}
	}

	// Prepend a line field for the start line (offset points at the line).
	root.Children = append([]*Field{c.newField(firstLine, "", base, nl)}, root.Children...)
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
	flow := tlsFlowFor(c)
	c.addLayer("tls")
	c.proto = "tls"

	root := c.newNode(fmt.Sprintf("Transport Layer Security (%s)", tlsContentTypeName(ct)), base, 5+recLen)
	root.add(
		c.newField(fmt.Sprintf("Content Type: %s (%d)", tlsContentTypeName(ct), ct), "", base, 1),
		c.newField(fmt.Sprintf("Version: %s (0x%04x)", tlsVersionName(ver), ver), "", base+1, 2),
		c.newField(fmt.Sprintf("Length: %d", recLen), "", base+3, 2),
	)

	body := b[5 : 5+recLen]
	c.m.Payload = body
	c.appInfo = tlsContentTypeName(ct)

	if ct == 22 && len(body) >= 4 {
		off := 0
		sawHS := false
		firstHT := byte(0)
		for off+4 <= len(body) {
			ht := body[off]
			hl := int(body[off+1])<<16 | int(body[off+2])<<8 | int(body[off+3])
			end := off + 4 + hl
			if end > len(body) {
				end = len(body)
			}
			if !sawHS {
				sawHS, firstHT = true, ht
			}
			c.parseTLSHandshakeMessage(ht, body[off+4:end], base+5+off+4, root, flow)
			off = end
		}
		if sawHS {
			c.appInfo = tlsHandshakeName(firstHT)
			if c.m.TLSSNI != "" {
				c.appInfo += " (SNI=" + c.m.TLSSNI + ")"
			}
		}
	} else if ct == 23 {
		root.add(c.newField(fmt.Sprintf("Encrypted Application Data (%d bytes)", len(body)), hexPreview(body, 32), base+5, len(body)))
		if c.noFields {
			// Summary mode only needs the record metadata; decryption is
			// deferred until the packet detail is opened.
			c.appInfo = fmt.Sprintf("Application Data (%d bytes)", len(body))
			c.addRoot(root)
			return true
		}
		if pt, inner, label, ok := flow.decryptRecord(c, b[:5], body); ok {
			dn := c.newNode(fmt.Sprintf("Decrypted TLS Record (%s)", tlsContentTypeName(inner)), base+5, recLen)
			dn.add(c.newField("Key Log Label: "+label, "", 0, 0))
			dn.add(c.newField(fmt.Sprintf("Inner Content Type: %s (%d)", tlsContentTypeName(inner), inner), "", 0, 0))
			switch inner {
			case 22:
				off := 0
				for off+4 <= len(pt) {
					ht := pt[off]
					hl := int(pt[off+1])<<16 | int(pt[off+2])<<8 | int(pt[off+3])
					end := off + 4 + hl
					if end > len(pt) {
						end = len(pt)
					}
					c.parseTLSHandshakeMessage(ht, pt[off+4:end], base+5, dn, flow)
					off = end
				}
			case 23:
				dn.add(c.newField(fmt.Sprintf("Decrypted Application Data (%d bytes)", len(pt)), printablePreview(pt, 300), 0, len(pt)))
				c.m.Payload = pt
				c.dissectDecryptedApp(pt, base+5)
				c.appInfo = fmt.Sprintf("Decrypted Application Data (%d bytes)", len(pt))
			case 21:
				if len(pt) >= 2 {
					dn.add(c.newField(fmt.Sprintf("Alert Level: %d, Description: %d", pt[0], pt[1]), "", 0, 2))
				}
			}
			root.add(dn)
		}
	} else if ct == 21 && len(body) >= 2 {
		root.add(c.newField(fmt.Sprintf("Alert Level: %d, Description: %d", body[0], body[1]), "", base+5, 2))
		c.appInfo = fmt.Sprintf("Alert (level %d, description %d)", body[0], body[1])
	}

	c.addRoot(root)
	return true
}

func bytesHasPrefixFold(b []byte, s string) bool {
	return len(b) >= len(s) && strings.EqualFold(string(b[:len(s)]), s)
}

func printablePreview(b []byte, n int) string {
	if len(b) > n {
		b = b[:n]
	}
	out := make([]rune, 0, len(b))
	for _, r := range string(b) {
		if r == '\r' || r == '\n' || r == '\t' || (r >= 32 && r < 127) {
			out = append(out, r)
		} else {
			out = append(out, '.')
		}
	}
	return string(out)
}

func (c *ctx) parseTLSHandshakeMessage(ht byte, b []byte, base int, root *Field, flow *tlsFlow) {
	hl := len(b)
	hsNode := c.newNode(fmt.Sprintf("%s (length %d)", tlsHandshakeName(ht), hl), base-4, min(hl+4, len(b)+4))
	switch ht {
	case 1:
		c.parseClientHello(b, base, hsNode, flow)
	case 2:
		c.parseServerHello(b, base, hsNode, flow)
	case 11:
		c.parseTLSCertificates(b, base, hsNode, flow)
	case 8:
		c.parseTLSExtensionsMessage(b, base, hsNode, flow, false)
	case 4: // NewSessionTicket
		if len(b) >= 4 {
			hsNode.add(c.newField(fmt.Sprintf("Ticket Lifetime: %d s", be32(b[0:4])), "", base, 4))
			if len(b) >= 8 {
				hsNode.add(c.newField(fmt.Sprintf("Ticket Age Add: %d", be32(b[4:8])), "", base+4, 4))
			}
		}
	case 15: // CertificateVerify
		if len(b) >= 4 {
			hsNode.add(c.newField(fmt.Sprintf("Signature Algorithm: 0x%04x", be16(b[0:2])), "", base, 2))
			if len(b) > 4 {
				hsNode.add(c.newField("Signature: "+hexPreview(b[4:], 64), "", base+4, len(b)-4))
			}
		}
	}
	root.add(hsNode)
}

func (c *ctx) parseTLSExtensionsMessage(b []byte, base int, node *Field, flow *tlsFlow, server bool) {
	if len(b) < 2 {
		return
	}
	l := int(be16(b[0:2]))
	if 2+l > len(b) {
		l = len(b) - 2
	}
	node.add(c.newField(fmt.Sprintf("Extensions Length: %d", l), "", base, 2))
	c.parseTLSExtensions(b[2:2+l], base+2, node, flow, server)
}

func tlsCipherName(s uint16) string {
	names := map[uint16]string{
		0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384",
		0x1303: "TLS_CHACHA20_POLY1305_SHA256", 0x1304: "TLS_AES_128_CCM_SHA256",
		0x1305: "TLS_AES_128_CCM_8_SHA256", 0xc02b: "TLS_ECDHE_ECDSA_AES128_GCM_SHA256",
		0xc02c: "TLS_ECDHE_ECDSA_AES256_GCM_SHA384", 0xc02f: "TLS_ECDHE_RSA_AES128_GCM_SHA256",
		0xc030: "TLS_ECDHE_RSA_AES256_GCM_SHA384", 0x009c: "TLS_RSA_AES128_GCM_SHA256",
		0x009d: "TLS_RSA_AES256_GCM_SHA384", 0xcca8: "TLS_ECDHE_RSA_CHACHA20_POLY1305",
		0xcca9: "TLS_ECDHE_ECDSA_CHACHA20_POLY1305",
	}
	if n := names[s]; n != "" {
		return n
	}
	return fmt.Sprintf("0x%04x", s)
}

func (c *ctx) parseClientHello(b []byte, base int, node *Field, flow *tlsFlow) {
	if len(b) < 34 {
		return
	}
	ver := be16(b[0:2])
	random := b[2:34]
	node.add(
		c.newField(fmt.Sprintf("Version: %s (0x%04x)", tlsVersionName(ver), ver), "", base, 2),
		c.newField("Random: "+hexPreview(random, 32), "", base+2, 32),
	)
	flow.observeClientHello(c, random)

	off := 34
	if off >= len(b) {
		return
	}
	sidLen := int(b[off])
	if off+1+sidLen > len(b) {
		return
	}
	node.add(c.newField(fmt.Sprintf("Session ID (%d bytes): %s", sidLen, hexPreview(b[off+1:off+1+sidLen], 24)), "", base+off, 1+sidLen))
	off += 1 + sidLen
	if off+2 > len(b) {
		return
	}
	csLen := int(be16(b[off : off+2]))
	csEnd := off + 2 + csLen
	if csEnd > len(b) {
		csEnd = len(b)
	}
	var suites []string
	for q := off + 2; q+2 <= csEnd; q += 2 {
		suites = append(suites, tlsCipherName(be16(b[q:q+2])))
	}
	node.add(c.newField(fmt.Sprintf("Cipher Suites (%d): %s", len(suites), strings.Join(suites, ", ")), "", base+off, 2+csLen))
	off = csEnd
	if off >= len(b) {
		return
	}
	compLen := int(b[off])
	node.add(c.newField(fmt.Sprintf("Compression Methods: %d", compLen), "", base+off, 1+compLen))
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
	if end > off {
		node.add(c.newField(fmt.Sprintf("Extensions (%d bytes)", extTotal), "", base+off-2, 2+end-off))
		c.parseTLSExtensions(b[off:end], base+off, node, flow, false)
	}
}

func (c *ctx) parseServerHello(b []byte, base int, node *Field, flow *tlsFlow) {
	if len(b) < 38 {
		return
	}
	legacy := be16(b[0:2])
	random := b[2:34]
	node.add(
		c.newField(fmt.Sprintf("Legacy Version: %s (0x%04x)", tlsVersionName(legacy), legacy), "", base, 2),
		c.newField("Random: "+hexPreview(random, 32), "", base+2, 32),
	)
	off := 34
	sidLen := int(b[off])
	if off+1+sidLen+3 > len(b) {
		return
	}
	node.add(c.newField(fmt.Sprintf("Session ID (%d bytes): %s", sidLen, hexPreview(b[off+1:off+1+sidLen], 24)), "", base+off, 1+sidLen))
	off += 1 + sidLen
	suite := be16(b[off : off+2])
	node.add(c.newField(fmt.Sprintf("Cipher Suite: %s (0x%04x)", tlsCipherName(suite), suite), "", base+off, 2))
	off += 2
	node.add(c.newField(fmt.Sprintf("Compression Method: %d", b[off]), "", base+off, 1))
	off++
	version := legacy
	if off+2 <= len(b) {
		extTotal := int(be16(b[off : off+2]))
		off += 2
		end := off + extTotal
		if end > len(b) {
			end = len(b)
		}
		if end > off {
			// supported_versions is parsed below and updates the actual version.
			c.parseTLSExtensions(b[off:end], base+off, node, flow, true)
			if v := flow.getVersion(); v != 0 {
				version = v
			}
		}
	}
	node.add(c.newField(fmt.Sprintf("Negotiated Version: %s", tlsVersionName(version)), "", base, 0))
	flow.observeServerHello(c, random, version, suite)
}

var tlsCertCache sync.Map // sha256(DER) -> *x509.Certificate

func tlsParseCert(der []byte) (*x509.Certificate, error) {
	key := sha256.Sum256(der)
	if v, ok := tlsCertCache.Load(key); ok {
		return v.(*x509.Certificate), nil
	}
	cert, err := x509.ParseCertificate(der)
	if err == nil {
		tlsCertCache.Store(key, cert)
	}
	return cert, err
}

func (c *ctx) parseTLSCertificates(b []byte, base int, node *Field, flow *tlsFlow) {
	if c.noFields {
		return
	}
	off := 0
	tlsVer := flow.getVersion()
	if tlsVer == 0x0304 {
		if len(b) < 1 {
			return
		}
		ctxLen := int(b[0])
		off = 1 + ctxLen
		if off+3 > len(b) {
			return
		}
		node.add(c.newField(fmt.Sprintf("Certificate Request Context (%d bytes)", ctxLen), hexPreview(b[1:1+ctxLen], 24), base, 1+ctxLen))
	}
	if off+3 > len(b) {
		return
	}
	listLen := int(b[off])<<16 | int(b[off+1])<<8 | int(b[off+2])
	off += 3
	end := off + listLen
	if end > len(b) {
		end = len(b)
	}
	node.add(c.newField(fmt.Sprintf("Certificate List Length: %d", listLen), "", base+off-3, 3))
	idx := 0
	for off+3 <= end {
		clen := int(b[off])<<16 | int(b[off+1])<<8 | int(b[off+2])
		off += 3
		if off+clen > end {
			break
		}
		der := b[off : off+clen]
		cf := c.newNode(fmt.Sprintf("Certificate %d (%d bytes)", idx+1, clen), base+off, clen)
		if cert, err := tlsParseCert(der); err == nil {
			cf.add(
				c.newField("Subject: "+cert.Subject.String(), "", 0, 0),
				c.newField("Issuer: "+cert.Issuer.String(), "", 0, 0),
				c.newField("Serial Number: "+cert.SerialNumber.String(), "", 0, 0),
				c.newField("Not Before: "+cert.NotBefore.UTC().Format("2006-01-02 15:04:05 MST"), "", 0, 0),
				c.newField("Not After: "+cert.NotAfter.UTC().Format("2006-01-02 15:04:05 MST"), "", 0, 0),
				c.newField("Signature Algorithm: "+cert.SignatureAlgorithm.String(), "", 0, 0),
				c.newField("Public Key Algorithm: "+cert.PublicKeyAlgorithm.String(), "", 0, 0),
			)
			if len(cert.DNSNames) > 0 {
				cf.add(c.newField("DNS Names: "+strings.Join(cert.DNSNames, ", "), "", 0, 0))
				if c.m.TLSSNI == "" {
					c.m.TLSSNI = cert.DNSNames[0]
				}
			}
			if len(cert.IPAddresses) > 0 {
				var ips []string
				for _, ip := range cert.IPAddresses {
					ips = append(ips, ip.String())
				}
				cf.add(c.newField("IP Addresses: "+strings.Join(ips, ", "), "", 0, 0))
			}
		} else {
			cf.add(c.newField("DER: "+hexPreview(der, 64), "", 0, 0), c.newField("Parse Error: "+err.Error(), "", 0, 0))
		}
		node.add(cf)
		off += clen
		idx++
		// TLS 1.3 per-certificate extensions.
		if tlsVer == 0x0304 && off+2 <= end {
			el := int(be16(b[off : off+2]))
			off += 2 + el
		}
	}
}

func (c *ctx) parseTLSExtensions(data []byte, base int, node *Field, flow *tlsFlow, server bool) {
	for off := 0; off+4 <= len(data); {
		etype := be16(data[off : off+2])
		elen := int(be16(data[off+2 : off+4]))
		if off+4+elen > len(data) {
			break
		}
		edata := data[off+4 : off+4+elen]
		name := tlsExtensionName(etype)
		f := c.newField(fmt.Sprintf("%s (%d bytes)", name, elen), "", base+off, 4+elen)
		switch etype {
		case 0: // server_name
			if len(edata) >= 5 {
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
						f.add(c.newField("Server Name: "+sni, "", base+off+4+p+3, nlen))
					}
					p += 3 + nlen
				}
			}
		case 16: // ALPN
			if len(edata) >= 2 {
				listLen := int(be16(edata[0:2]))
				p := 2
				for p < len(edata) && p < 2+listLen {
					l := int(edata[p])
					p++
					if p+l > len(edata) {
						break
					}
					proto := string(edata[p : p+l])
					f.add(c.newField("ALPN Protocol: "+proto, "", base+off+4+p, l))
					p += l
				}
			}
		case 10: // supported_groups
			if len(edata) >= 2 {
				l := int(be16(edata[0:2]))
				var groups []string
				for q := 2; q+2 <= len(edata) && q < 2+l; q += 2 {
					groups = append(groups, tlsGroupName(be16(edata[q:q+2])))
				}
				f.add(c.newField("Supported Groups: "+strings.Join(groups, ", "), "", base+off+4, len(edata)))
			}
		case 13: // signature_algorithms
			if len(edata) >= 2 {
				l := int(be16(edata[0:2]))
				var algs []string
				for q := 2; q+2 <= len(edata) && q < 2+l; q += 2 {
					algs = append(algs, fmt.Sprintf("0x%04x", be16(edata[q:q+2])))
				}
				f.add(c.newField("Signature Algorithms: "+strings.Join(algs, ", "), "", base+off+4, len(edata)))
			}
		case 43: // supported_versions
			if server {
				if len(edata) >= 2 {
					v := be16(edata[0:2])
					flow.setVersion(v)
					f.add(c.newField("Selected Version: "+tlsVersionName(v), "", base+off+4, 2))
				}
			} else if len(edata) >= 1 {
				l := int(edata[0])
				var vs []string
				for q := 1; q+2 <= len(edata) && q < 1+l; q += 2 {
					vs = append(vs, tlsVersionName(be16(edata[q:q+2])))
				}
				f.add(c.newField("Supported Versions: "+strings.Join(vs, ", "), "", base+off+4, len(edata)))
			}
		case 51: // key_share
			if server {
				if len(edata) >= 4 {
					g := be16(edata[0:2])
					l := int(be16(edata[2:4]))
					if 4+l <= len(edata) {
						f.add(c.newField("Selected Group: "+tlsGroupName(g), "", base+off+4, 2), c.newField("Key Exchange: "+hexPreview(edata[4:4+l], 48), "", base+off+6, l))
					}
				}
			} else if len(edata) >= 2 {
				listLen := int(be16(edata[0:2]))
				p := 2
				for p+4 <= len(edata) && p < 2+listLen {
					g := be16(edata[p : p+2])
					l := int(be16(edata[p+2 : p+4]))
					if p+4+l > len(edata) {
						break
					}
					f.add(c.newField("Key Share "+tlsGroupName(g)+": "+hexPreview(edata[p+4:p+4+l], 48), "", base+off+4+p, 4+l))
					p += 4 + l
				}
			}
		default:
			if elen > 0 {
				f.Value = hexPreview(edata, 32)
			}
		}
		node.add(f)
		off += 4 + elen
	}
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
