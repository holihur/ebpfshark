//go:build full

package decode

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------- SNMP BER

type berTLV struct {
	tag   byte
	value []byte
	next  int
}

func berRead(b []byte, off int) (berTLV, bool) {
	if off >= len(b) {
		return berTLV{}, false
	}
	tag := b[off]
	off++
	if off >= len(b) {
		return berTLV{}, false
	}
	l := int(b[off])
	off++
	if l&0x80 != 0 {
		n := l & 0x7f
		if n == 0 || n > 4 || off+n > len(b) {
			return berTLV{}, false
		}
		l = 0
		for i := 0; i < n; i++ {
			l = l<<8 | int(b[off+i])
		}
		off += n
	}
	if off+l > len(b) {
		l = len(b) - off
	}
	return berTLV{tag: tag, value: b[off : off+l], next: off + l}, true
}

func berInt(b []byte) int64 {
	var v int64
	for _, x := range b {
		v = v<<8 | int64(x)
	}
	return v
}

func berOID(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	parts := []int{int(b[0]) / 40, int(b[0]) % 40}
	v := 0
	for _, x := range b[1:] {
		v = v<<7 | int(x&0x7f)
		if x&0x80 == 0 {
			parts = append(parts, v)
			v = 0
		}
	}
	var sb strings.Builder
	for i, p := range parts {
		if i > 0 {
			sb.WriteByte('.')
		}
		sb.WriteString(strconv.Itoa(p))
	}
	return sb.String()
}

func berValue(t berTLV) string {
	switch t.tag {
	case 0x05:
		return "NULL"
	case 0x02:
		return strconv.FormatInt(berInt(t.value), 10)
	case 0x04:
		return shorten(string(t.value), 120)
	case 0x06:
		return berOID(t.value)
	case 0x40:
		if len(t.value) == 4 {
			return netip.AddrFrom4([4]byte{t.value[0], t.value[1], t.value[2], t.value[3]}).String()
		}
	case 0x41, 0x42, 0x43:
		return strconv.FormatInt(berInt(t.value), 10)
	}
	if len(t.value) == 0 {
		return ""
	}
	return hexPreview(t.value, 32)
}

var snmpPDUNames = map[byte]string{
	0xA0: "GET-REQUEST", 0xA1: "GET-NEXT-REQUEST", 0xA2: "GET-RESPONSE",
	0xA3: "SET-REQUEST", 0xA4: "TRAP-V1", 0xA5: "GET-BULK-REQUEST",
	0xA6: "INFORM-REQUEST", 0xA7: "TRAP-V2", 0xA8: "REPORT",
}

func snmpVersion(v int64) string {
	switch v {
	case 0:
		return "v1"
	case 1:
		return "v2c"
	case 3:
		return "v3"
	}
	return fmt.Sprintf("version %d", v)
}

func snmpErrorStatus(v int64) string {
	names := []string{"noError", "tooBig", "noSuchName", "badValue", "readOnly", "genErr", "noAccess", "wrongType", "wrongLength", "wrongEncoding", "wrongValue", "noCreation", "inconsistentValue", "resourceUnavailable", "commitFailed", "undoFailed", "authorizationError", "notWritable", "inconsistentName"}
	if int(v) >= 0 && int(v) < len(names) {
		return names[v]
	}
	return fmt.Sprintf("status %d", v)
}

func snmpVarbinds(c *ctx, list []byte, root *Field, base int) string {
	first := ""
	pos := 0
	for i := 0; i < 128; i++ {
		vb, ok := berRead(list, pos)
		if !ok || vb.tag != 0x30 {
			break
		}
		pos = vb.next
		o, ok := berRead(vb.value, 0)
		if !ok || o.tag != 0x06 {
			continue
		}
		oid := berOID(o.value)
		if first == "" {
			first = oid
		}
		val, ok := berRead(vb.value, o.next)
		if !ok {
			root.add(c.newField(oid+" = <missing>", "", base, 0))
			continue
		}
		switch val.tag {
		case 0x80:
			root.add(c.newField(oid+" = noSuchObject", "", base, 0))
		case 0x81:
			root.add(c.newField(oid+" = noSuchInstance", "", base, 0))
		case 0x82:
			root.add(c.newField(oid+" = endOfMibView", "", base, 0))
		default:
			root.add(c.newField(oid+" = "+berValue(val), "", base, 0))
		}
	}
	return first
}

func snmpPDU(c *ctx, pdu berTLV, root *Field, base int) (string, string) {
	name := snmpPDUNames[pdu.tag]
	if name == "" {
		return "", ""
	}
	info := name
	pos := 0
	if pdu.tag == 0xA4 { // SNMPv1 Trap-PDU
		ent, ok := berRead(pdu.value, pos)
		if ok && ent.tag == 0x06 {
			root.add(c.newField("Enterprise: "+berOID(ent.value), "", base, 0))
			pos = ent.next
		}
		agent, ok := berRead(pdu.value, pos)
		if ok && agent.tag == 0x40 {
			root.add(c.newField("Agent Address: "+berValue(agent), "", base, 0))
			pos = agent.next
		}
		gen, ok := berRead(pdu.value, pos)
		if ok {
			gn := map[int64]string{0: "coldStart", 1: "warmStart", 2: "linkDown", 3: "linkUp", 4: "authenticationFailure", 5: "egpNeighborLoss", 6: "enterpriseSpecific"}[berInt(gen.value)]
			root.add(c.newField(fmt.Sprintf("Generic Trap: %s (%d)", gn, berInt(gen.value)), "", base, 0))
			pos = gen.next
			info += " " + gn
		}
		spec, ok := berRead(pdu.value, pos)
		if ok {
			root.add(c.newField(fmt.Sprintf("Specific Trap: %d", berInt(spec.value)), "", base, 0))
			pos = spec.next
		}
		ts, ok := berRead(pdu.value, pos)
		if ok {
			root.add(c.newField(fmt.Sprintf("Time Stamp: %d", berInt(ts.value)), "", base, 0))
			pos = ts.next
		}
	} else {
		req, ok := berRead(pdu.value, pos)
		if ok {
			root.add(c.newField(fmt.Sprintf("Request ID: %d", berInt(req.value)), "", base, 0))
			pos = req.next
		}
		st, ok := berRead(pdu.value, pos)
		if ok {
			label := "Error Status"
			if pdu.tag == 0xA5 {
				label = "Non-repeaters"
			}
			root.add(c.newField(fmt.Sprintf("%s: %s (%d)", label, snmpErrorStatus(berInt(st.value)), berInt(st.value)), "", base, 0))
			pos = st.next
		}
		idx, ok := berRead(pdu.value, pos)
		if ok {
			label := "Error Index"
			if pdu.tag == 0xA5 {
				label = "Max Repetitions"
			}
			root.add(c.newField(fmt.Sprintf("%s: %d", label, berInt(idx.value)), "", base, 0))
			pos = idx.next
		}
	}
	vbs, ok := berRead(pdu.value, pos)
	if ok && vbs.tag == 0x30 {
		oid := snmpVarbinds(c, vbs.value, root, base)
		if oid != "" {
			info += " " + oid
		}
	}
	return name, info
}

func (c *ctx) dissectSNMP(b []byte, base int) bool {
	if len(b) < 4 || b[0] != 0x30 {
		return false
	}
	outer, ok := berRead(b, 0)
	if !ok {
		return false
	}
	ver, ok := berRead(outer.value, 0)
	if !ok || ver.tag != 0x02 {
		return false
	}
	version := berInt(ver.value)
	if version != 0 && version != 1 && version != 3 {
		return false
	}
	c.addLayer("snmp")
	c.proto = "snmp"
	root := c.newNode("Simple Network Management Protocol", base, len(b))
	root.add(c.newField(fmt.Sprintf("Version: %s (%d)", snmpVersion(version), version), "", base, 0))
	info := "SNMP " + snmpVersion(version)

	if version == 3 {
		header, ok := berRead(outer.value, ver.next)
		if !ok || header.tag != 0x30 {
			return false
		}
		hpos := 0
		msgID, ok := berRead(header.value, hpos)
		if ok {
			root.add(c.newField(fmt.Sprintf("Message ID: %d", berInt(msgID.value)), "", base, 0))
			hpos = msgID.next
		}
		maxSize, ok := berRead(header.value, hpos)
		if ok {
			root.add(c.newField(fmt.Sprintf("Max Message Size: %d", berInt(maxSize.value)), "", base, 0))
			hpos = maxSize.next
		}
		flags, ok := berRead(header.value, hpos)
		if ok {
			fv := byte(0)
			if len(flags.value) > 0 {
				fv = flags.value[0]
			}
			root.add(c.newField(fmt.Sprintf("Flags: 0x%02x (auth=%d priv=%d reportable=%d)", fv, (fv>>0)&1, (fv>>1)&1, (fv>>2)&1), "", base, 0))
			hpos = flags.next
		}
		secModel, ok := berRead(header.value, hpos)
		if ok {
			root.add(c.newField(fmt.Sprintf("Security Model: %d", berInt(secModel.value)), "", base, 0))
		}
		sec, ok := berRead(outer.value, header.next)
		if !ok || sec.tag != 0x04 {
			return false
		}
		usm, ok := berRead(sec.value, 0)
		if ok && usm.tag == 0x30 {
			up := 0
			names := []string{"Engine ID", "Engine Boots", "Engine Time", "User Name", "Authentication Parameters", "Privacy Parameters"}
			for i := 0; i < len(names); i++ {
				t, ok := berRead(usm.value, up)
				if !ok {
					break
				}
				up = t.next
				val := string(t.value)
				if i == 0 || i == 3 || i == 4 || i == 5 {
					val = hexPreview(t.value, 32)
					if t.tag == 0x04 && i == 3 {
						val = string(t.value)
					}
				}
				if i == 1 || i == 2 {
					val = strconv.FormatInt(berInt(t.value), 10)
				}
				root.add(c.newField(names[i]+": "+val, "", base, 0))
				if i == 3 {
					info += " user=" + string(t.value)
				}
			}
		}
		data, ok := berRead(outer.value, sec.next)
		if !ok || data.tag != 0x30 {
			return false
		}
		dpos := 0
		if ce, ok := berRead(data.value, dpos); ok {
			root.add(c.newField("Context Engine ID: "+hexPreview(ce.value, 32), "", base, 0))
			dpos = ce.next
		}
		if cn, ok := berRead(data.value, dpos); ok {
			root.add(c.newField("Context Name: "+string(cn.value), "", base, 0))
			dpos = cn.next
		}
		scoped, ok := berRead(data.value, dpos)
		if !ok {
			return false
		}
		if scoped.tag == 0x04 {
			root.add(c.newField("Encrypted PDU: "+hexPreview(scoped.value, 64), "", base, 0))
			info += " encrypted"
		} else if name, pduInfo := snmpPDU(c, scoped, root, base); name != "" {
			root.Label = "Simple Network Management Protocol (" + name + ")"
			root.add(c.newField(fmt.Sprintf("PDU: %s (0x%02x)", name, scoped.tag), "", base, 0))
			info += " " + pduInfo
		}
	} else {
		community, ok := berRead(outer.value, ver.next)
		if !ok || community.tag != 0x04 {
			return false
		}
		pdu, ok := berRead(outer.value, community.next)
		if !ok {
			return false
		}
		name, pduInfo := snmpPDU(c, pdu, root, base)
		if name == "" {
			return false
		}
		root.Label = "Simple Network Management Protocol (" + name + ")"
		root.add(c.newField("Community: "+string(community.value), "", base, 0), c.newField(fmt.Sprintf("PDU: %s (0x%02x)", name, pdu.tag), "", base, 0))
		info += " " + name + " community=" + string(community.value) + " " + pduInfo
	}
	c.addRoot(root)
	c.appInfo = shorten(info, 120)
	return true
}

func init() {
	RegisterPlugin(pluginSpec{Name: "snmp", Priority: 40, Transport: TransportUDP,
		Match: portMatch(map[uint16]bool{161: true, 162: true}), Dissect: func(c *ctx, b []byte, base int) bool { return c.dissectSNMP(b, base) }})
}
