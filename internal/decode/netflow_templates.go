//go:build full

package decode

import (
	"fmt"
	"net/netip"
	"sync"
)

type netflowField struct {
	typ    uint16
	length int
}

type netflowTemplate struct {
	fields []netflowField
}

var netflowTemplates = struct {
	sync.Mutex
	m map[string]map[uint16]netflowTemplate
}{m: make(map[string]map[uint16]netflowTemplate)}

func netflowFieldName(t uint16) string {
	names := map[uint16]string{
		1: "IN_BYTES", 2: "IN_PKTS", 4: "PROTOCOL", 5: "SRC_TOS", 6: "TCP_FLAGS",
		7: "L4_SRC_PORT", 8: "IPV4_SRC_ADDR", 9: "SRC_MASK", 10: "INPUT_SNMP",
		11: "L4_DST_PORT", 12: "IPV4_DST_ADDR", 13: "DST_MASK", 14: "OUTPUT_SNMP",
		15: "IPV4_NEXT_HOP", 16: "SRC_AS", 17: "DST_AS", 18: "BGP_NEXT_AS",
		21: "LAST_SWITCHED", 22: "FIRST_SWITCHED", 23: "OUT_BYTES", 24: "OUT_PKTS",
		27: "IPV6_SRC_ADDR", 28: "IPV6_DST_ADDR", 29: "IPV6_SRC_MASK", 30: "IPV6_DST_MASK",
		31: "IPV6_FLOW_LABEL", 32: "ICMP_TYPE", 33: "MUL_IGMP_TYPE", 34: "SAMPLING_INTERVAL",
		35: "SAMPLING_ALGORITHM", 38: "ENGINE_TYPE", 39: "ENGINE_ID", 40: "TOTAL_BYTES_EXP",
		41: "TOTAL_PKTS_EXP", 42: "TOTAL_FLOWS_EXP", 46: "MPLS_TOP_LABEL_TYPE", 47: "MPLS_TOP_LABEL_IP_ADDR",
		48: "FLOW_SAMPLER_ID", 49: "FLOW_SAMPLER_MODE", 50: "FLOW_SAMPLER_RANDOM_INTERVAL",
		52: "MIN_TTL", 53: "MAX_TTL", 54: "IPV4_IDENT", 55: "DST_TOS", 56: "IN_SRC_MAC",
		57: "OUT_DST_MAC", 58: "SRC_VLAN", 59: "DST_VLAN", 60: "IP_PROTOCOL_VERSION",
		61: "DIRECTION", 62: "IPV6_NEXT_HOP", 63: "BGP_IPV6_NEXT_HOP", 64: "IPV6_OPTION_HEADERS",
		70: "MPLS_LABEL_1", 71: "MPLS_LABEL_2", 72: "MPLS_LABEL_3", 73: "MPLS_LABEL_4",
		74: "MPLS_LABEL_5", 75: "MPLS_LABEL_6", 76: "MPLS_LABEL_7", 77: "MPLS_LABEL_8",
		78: "MPLS_LABEL_9", 79: "MPLS_LABEL_10", 80: "IN_DST_MAC", 81: "OUT_SRC_MAC",
		82: "IF_NAME", 83: "IF_DESC", 84: "SAMPLER_NAME", 85: "IN_PERMANENT_BYTES",
		86: "IN_PERMANENT_PKTS", 88: "FRAGMENT_OFFSET", 89: "FORWARDING_STATUS",
	}
	if n := names[t]; n != "" {
		return n
	}
	return fmt.Sprintf("Field-%d", t)
}

func netflowValue(t uint16, v []byte) string {
	switch t {
	case 8, 12, 15, 18, 47:
		if len(v) == 4 {
			return netip.AddrFrom4([4]byte{v[0], v[1], v[2], v[3]}).String()
		}
	case 27, 28, 62, 63:
		if len(v) == 16 {
			var a [16]byte
			copy(a[:], v)
			return netip.AddrFrom16(a).String()
		}
	case 56, 57, 80, 81:
		if len(v) == 6 {
			return macString(v)
		}
	case 7, 11, 32, 34, 50, 54, 58, 59, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79:
		if len(v) <= 4 {
			return fmt.Sprintf("%d", beUint(v))
		}
	case 4, 5, 6, 9, 13, 29, 30, 35, 38, 39, 46, 48, 49, 52, 53, 55, 60, 61, 64, 88, 89:
		if len(v) <= 4 {
			return fmt.Sprintf("%d", beUint(v))
		}
	case 21, 22:
		if len(v) <= 8 {
			return fmt.Sprintf("%d ms", beUint(v))
		}
	}
	return hexPreview(v, 32)
}

func beUint(b []byte) uint64 {
	var out uint64
	for _, x := range b {
		out = out<<8 | uint64(x)
	}
	return out
}

func netflowTemplateKey(c *ctx, domain uint32) string {
	return fmt.Sprintf("%s|%d|%d", c.m.SrcIP, c.m.SrcPort, domain)
}

func parseNetFlowSets(c *ctx, b []byte, base, off int, version int, domain uint32, root *Field, info *string) {
	key := netflowTemplateKey(c, domain)
	netflowTemplates.Lock()
	tpls := netflowTemplates.m[key]
	if tpls == nil {
		tpls = make(map[uint16]netflowTemplate)
		netflowTemplates.m[key] = tpls
	}
	if len(netflowTemplates.m) > 2048 {
		for k := range netflowTemplates.m {
			if k != key {
				delete(netflowTemplates.m, k)
			}
			if len(netflowTemplates.m) < 1024 {
				break
			}
		}
	}
	netflowTemplates.Unlock()

	for off+4 <= len(b) {
		setID := be16(b[off : off+2])
		l := int(be16(b[off+2 : off+4]))
		if l < 4 || off+l > len(b) {
			break
		}
		set := c.newField(fmt.Sprintf("Set %d (%d bytes)", setID, l), "", base+off, l)
		templateSet := (version == 9 && setID == 0) || (version == 10 && setID == 2)
		optionsSet := version == 10 && setID == 3
		if templateSet || optionsSet {
			parseNetFlowTemplateSet(c, b[off+4:off+l], base+off+4, set, version, tpls, optionsSet)
			root.add(set)
			*info = fmt.Sprintf("NetFlow v%d template", version)
			off += l
			continue
		}
		if setID >= 256 {
			if tpl, ok := tpls[setID]; ok {
				n := parseNetFlowData(c, b[off+4:off+l], base+off+4, set, tpl)
				*info = fmt.Sprintf("NetFlow v%d %d records", version, n)
			} else {
				set.add(c.newField(fmt.Sprintf("Data Set (template %d unknown)", setID), "", base+off+4, l-4))
			}
		}
		root.add(set)
		off += l
	}
}

func parseNetFlowTemplateSet(c *ctx, b []byte, base int, root *Field, version int, tpls map[uint16]netflowTemplate, options bool) {
	off := 0
	for off+4 <= len(b) {
		id := be16(b[off : off+2])
		count := int(be16(b[off+2 : off+4]))
		off += 4
		if count <= 0 || count > 256 {
			break
		}
		fields := make([]netflowField, 0, count)
		if options && off >= len(b) {
			break
		}
		if options {
			off += 2
		} // scope length (IPFIX options template)
		ok := true
		for i := 0; i < count; i++ {
			if off+4 > len(b) {
				ok = false
				break
			}
			t, l := be16(b[off:off+2]), int(be16(b[off+2:off+4]))
			off += 4
			if version == 10 && t&0x8000 != 0 {
				t &^= 0x8000
				if off+4 > len(b) {
					ok = false
					break
				}
				off += 4 // enterprise number
			}
			if l == 0 || l > 65535 {
				ok = false
				break
			}
			fields = append(fields, netflowField{t, l})
		}
		if !ok {
			break
		}
		if !options && id >= 256 {
			tpls[id] = netflowTemplate{fields: fields}
			n := c.newField(fmt.Sprintf("Template %d (%d fields)", id, count), "", base+off, 0)
			for _, f := range fields {
				n.add(c.newField(fmt.Sprintf("%s (%d bytes)", netflowFieldName(f.typ), f.length), "", base, 0))
			}
			root.add(n)
		}
	}
}

func parseNetFlowData(c *ctx, b []byte, base int, root *Field, tpl netflowTemplate) int {
	off := 0
	n := 0
	for off < len(b) && n < 64 {
		start := off
		rec := c.newNode(fmt.Sprintf("Record %d", n+1), base+off, 0)
		for _, f := range tpl.fields {
			l := f.length
			if l == 65535 { // IPFIX variable length
				if off >= len(b) {
					return n
				}
				l = int(b[off])
				off++
				if l&0x80 != 0 {
					if off+int(l&0x7f) > len(b) {
						return n
					}
					l = 0
					for i := 0; i < int(b[off]&0x7f); i++ {
						l = l<<8 | int(b[off+1+i])
					}
					off += int(b[off]&0x7f) + 1
				}
			}
			if l < 0 || off+l > len(b) {
				return n
			}
			v := b[off : off+l]
			rec.add(c.newField(netflowFieldName(f.typ), netflowValue(f.typ, v), base+off, l))
			off += l
		}
		if off == start {
			break
		}
		root.add(rec)
		n++
	}
	return n
}
