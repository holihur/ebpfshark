package decode

import (
	"fmt"
	"net/netip"
	"strings"
)

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

func init() {
	RegisterPlugin(pluginSpec{Name: "dns", Priority: 10, Transport: TransportUDP | TransportTCP,
		Match: portMatch(dnsPorts), Dissect: func(c *ctx, b []byte, base int) bool {
			return c.dissectDNS(b, base, c.m.HasLayer("tcp"))
		}})
}
