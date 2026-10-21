package decode

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"ebpfshark/internal/packet"
)

// ------------------------------------------------------------ IGMP / MPLS / GRE

func igmpTypeName(t byte) string {
	switch t {
	case 0x11:
		return "Membership Query"
	case 0x12:
		return "V1 Membership Report"
	case 0x16:
		return "V2 Membership Report"
	case 0x17:
		return "Leave Group"
	case 0x22:
		return "V3 Membership Report"
	}
	return fmt.Sprintf("Type 0x%02x", t)
}

func igmpMaxResp(code byte) string {
	if code < 128 {
		return fmt.Sprintf("%d (0.1s)", code)
	}
	exp := (code >> 4) & 0x7
	mant := code & 0xf
	return fmt.Sprintf("%d (coded 0x%02x)", (mant|0x10)<<(exp+3), code)
}

var igmpRecordNames = map[byte]string{
	1: "MODE_IS_INCLUDE", 2: "MODE_IS_EXCLUDE", 3: "CHANGE_TO_INCLUDE_MODE",
	4: "CHANGE_TO_EXCLUDE_MODE", 5: "ALLOW_NEW_SOURCES", 6: "BLOCK_OLD_SOURCES",
}

func igmpSources(b []byte, base, off, count int) []string {
	var out []string
	for i := 0; i < count && off+4 <= len(b); i++ {
		out = append(out, netip.AddrFrom4([4]byte{b[off], b[off+1], b[off+2], b[off+3]}).String())
		off += 4
	}
	return out
}

func (c *ctx) dissectIGMP(b []byte, base int) {
	c.addLayer("igmp")
	c.proto = "igmp"
	if len(b) < 8 {
		c.addRoot(newNode("Internet Group Management Protocol (truncated)", base, len(b)))
		return
	}
	typ := b[0]
	name := igmpTypeName(typ)
	group := netip.AddrFrom4([4]byte{b[4], b[5], b[6], b[7]}).String()
	root := newNode("Internet Group Management Protocol ("+name+")", base, len(b))
	root.add(
		newField(fmt.Sprintf("Type: %s (0x%02x)", name, typ), "", base, 1),
		newField("Checksum: "+fmt.Sprintf("0x%04x", be16(b[2:4])), "", base+2, 2),
	)
	info := name + " " + group

	switch typ {
	case 0x11: // query
		root.add(newField("Max Response Time: "+igmpMaxResp(b[1]), "", base+1, 1))
		root.add(newField("Group Address: "+group, "", base+4, 4))
		if len(b) >= 12 {
			nsrc := int(be16(b[10:12]))
			root.add(
				newField(fmt.Sprintf("Reserved/Suppress: 0x%02x", b[8]), "", base+8, 1),
				newField(fmt.Sprintf("QQIC: %d", b[9]), "", base+9, 1),
				newField(fmt.Sprintf("Number of Sources: %d", nsrc), "", base+10, 2),
			)
			srcs := igmpSources(b, base, 12, nsrc)
			for i, src := range srcs {
				root.add(newField(fmt.Sprintf("Source %d: %s", i+1, src), "", base+12+i*4, 4))
			}
			if nsrc > 0 {
				info += fmt.Sprintf(" sources=%d", nsrc)
			}
		} else {
			root.add(newField("Max Response Time: "+igmpMaxResp(b[1]), "", base+1, 1))
		}
	case 0x22: // v3 report
		nrec := int(be16(b[6:8]))
		root.add(
			newField(fmt.Sprintf("Reserved: 0x%04x", be16(b[4:6])), "", base+4, 2),
			newField(fmt.Sprintf("Number of Group Records: %d", nrec), "", base+6, 2),
		)
		off := 8
		for i := 0; i < nrec && off+8 <= len(b); i++ {
			rtype := b[off]
			auxLen := int(b[off+1])
			nsrc := int(be16(b[off+2 : off+4]))
			grp := netip.AddrFrom4([4]byte{b[off+4], b[off+5], b[off+6], b[off+7]})
			rname := igmpRecordNames[rtype]
			if rname == "" {
				rname = fmt.Sprintf("Record Type %d", rtype)
			}
			f := newField(fmt.Sprintf("%s group=%s sources=%d", rname, grp, nsrc), "", base+off, 8+auxLen+nsrc*4)
			f.add(
				newField(fmt.Sprintf("Record Type: %s (%d)", rname, rtype), "", base+off, 1),
				newField(fmt.Sprintf("Auxiliary Data Length: %d", auxLen), "", base+off+1, 1),
				newField(fmt.Sprintf("Number of Sources: %d", nsrc), "", base+off+2, 2),
				newField("Multicast Group: "+grp.String(), "", base+off+4, 4),
			)
			p := off + 8
			if auxLen > 0 {
				if p+auxLen > len(b) {
					break
				}
				f.add(newField("Auxiliary Data: "+hexPreview(b[p:p+auxLen], 32), "", base+p, auxLen))
				p += auxLen
			}
			for j := 0; j < nsrc && p+4 <= len(b); j++ {
				src := netip.AddrFrom4([4]byte{b[p], b[p+1], b[p+2], b[p+3]})
				f.add(newField(fmt.Sprintf("Source %d: %s", j+1, src), "", base+p, 4))
				p += 4
			}
			root.add(f)
			off = p
		}
		info = fmt.Sprintf("IGMPv3 report records=%d", nrec)
	default:
		root.add(
			newField("Max Response Time: "+igmpMaxResp(b[1]), "", base+1, 1),
			newField("Group Address: "+group, "", base+4, 4),
		)
	}

	c.addRoot(root)
	c.appInfo = info
}

func (c *ctx) dissectMPLS(b []byte, base int) {
	c.addLayer("mpls")
	c.proto = "mpls"
	root := newNode("MultiProtocol Label Switching Header", base, len(b))
	off := 0
	firstLabel := -1
	for i := 0; i < 8 && off+4 <= len(b); i++ {
		entry := be32(b[off : off+4])
		label := (entry >> 12) & 0xfffff
		tc := (entry >> 9) & 0x7
		bos := (entry >> 8) & 1
		ttl := entry & 0xff
		if firstLabel < 0 {
			firstLabel = int(label)
		}
		root.add(newField(fmt.Sprintf("Label %d: %d, TC: %d, S: %d, TTL: %d", i, label, tc, bos, ttl), "", base+off, 4))
		off += 4
		if bos == 1 {
			break
		}
	}
	c.addRoot(root)
	if off < len(b) {
		switch b[off] >> 4 {
		case 4:
			c.dissectIPv4(b[off:], base+off)
		case 6:
			c.dissectIPv6(b[off:], base+off)
		default:
			c.dissectData(b[off:], base+off)
		}
	}
	if firstLabel >= 0 {
		c.appInfo = fmt.Sprintf("MPLS label %d", firstLabel)
	} else {
		c.appInfo = "MPLS"
	}
	c.proto = "mpls"
}

func (c *ctx) addInnerFrame(b []byte, base int, label string) {
	if len(b) == 0 {
		return
	}
	if c.depth >= maxTunnelDepth {
		c.addRoot(newField(label+" (tunnel depth limit)", "", base, len(b)))
		return
	}
	res := decode(b, packet.LinkEthernet, len(b), c.depth+1)
	group := newNode(label, base, len(b))
	group.Children = shiftFields(res.Fields, base)
	c.addRoot(group)
}

func (c *ctx) dissectGRE(b []byte, base int) {
	c.addLayer("gre")
	c.proto = "gre"
	if len(b) < 4 {
		c.addRoot(newNode("Generic Routing Encapsulation (truncated)", base, len(b)))
		return
	}
	flags := be16(b[0:2])
	version := flags & 0x7
	proto := be16(b[2:4])
	off := 4
	if flags&0x8000 != 0 { // checksum present
		off += 4
	}
	if flags&0x2000 != 0 { // key present
		off += 4
	}
	if flags&0x1000 != 0 { // sequence present
		off += 4
	}
	if off > len(b) {
		off = len(b)
	}
	root := newNode("Generic Routing Encapsulation", base, len(b))
	root.add(
		newField(fmt.Sprintf("Flags: 0x%04x", flags), "", base, 2),
		newField(fmt.Sprintf("Version: %d", version), "", base, 1),
		newField(fmt.Sprintf("Protocol Type: %s (0x%04x)", etherTypeName(proto), proto), "", base+2, 2),
	)
	c.addRoot(root)
	if off < len(b) {
		switch proto {
		case etherTypeIPv4:
			c.dissectIPv4(b[off:], base+off)
		case etherTypeIPv6:
			c.dissectIPv6(b[off:], base+off)
		case etherTypeARP:
			c.dissectARP(b[off:], base+off)
		case 0x6558: // transparent Ethernet bridging
			c.addInnerFrame(b[off:], base+off, "Inner Ethernet frame")
		default:
			c.dissectData(b[off:], base+off)
		}
	}
	c.proto = "gre"
	c.appInfo = "GRE " + etherTypeName(proto)
}

// ------------------------------------------------------- DHCP (full options)

var dhcpOptionNames = map[byte]string{
	1: "Subnet Mask", 2: "Time Offset", 3: "Router", 4: "Time Server", 5: "Name Server",
	6: "Domain Name Server", 7: "Log Server", 8: "Cookie Server", 9: "LPR Server",
	10: "Impress Server", 11: "Resource Location Server", 12: "Host Name", 13: "Boot File Size",
	14: "Merit Dump File", 15: "Domain Name", 16: "Swap Server", 17: "Root Path",
	18: "Extensions Path", 19: "IP Forwarding", 20: "Non-Local Source Routing",
	21: "Policy Filter", 22: "Maximum Datagram Reassembly Size", 23: "Default IP TTL",
	24: "Path MTU Aging Timeout", 25: "Path MTU Plateau Table", 26: "Interface MTU",
	27: "All Subnets Are Local", 28: "Broadcast Address", 29: "Perform Mask Discovery",
	30: "Mask Supplier", 31: "Perform Router Discovery", 32: "Router Solicitation Address",
	33: "Static Route", 34: "Trailer Encapsulation", 35: "ARP Cache Timeout",
	36: "Ethernet Encapsulation", 37: "TCP Default TTL", 38: "TCP Keepalive Interval",
	39: "TCP Keepalive Garbage", 40: "Network Information Service Domain",
	41: "Network Information Service Servers", 42: "NTP Servers", 43: "Vendor Specific",
	44: "NetBIOS over TCP/IP Name Server", 45: "NetBIOS over TCP/IP Datagram Distribution Server",
	46: "NetBIOS over TCP/IP Node Type", 47: "NetBIOS over TCP/IP Scope", 48: "X Window System Font Server",
	49: "X Window System Display Manager", 50: "Requested IP Address", 51: "IP Address Lease Time",
	52: "Option Overload", 53: "DHCP Message Type", 54: "Server Identifier", 55: "Parameter Request List",
	56: "Message", 57: "Maximum DHCP Message Size", 58: "Renewal Time Value", 59: "Rebinding Time Value",
	60: "Vendor Class Identifier", 61: "Client Identifier", 64: "NIS+ Domain", 65: "NIS+ Servers",
	66: "TFTP Server Name", 67: "Bootfile Name", 68: "Mobile IP Home Agent", 69: "SMTP Server",
	70: "POP3 Server", 71: "NNTP Server", 72: "WWW Server", 73: "Finger Server", 74: "IRC Server",
	75: "StreetTalk Server", 76: "StreetTalk Directory Assistance Server", 80: "Rapid Commit",
	81: "Client FQDN", 82: "Relay Agent Information", 91: "Client Last Transaction Time",
	93: "Client System Architecture", 94: "Client Network Interface Identifier", 97: "Client UUID/GUID",
	119: "Domain Search", 121: "Classless Static Route", 125: "Vendor-Identifying Vendor Options",
	208: "PXE Magic", 209: "PXE Configuration File", 210: "PXE Path Prefix", 211: "PXE Reboot Time",
	212: "PXE 6rd", 213: "PXE Boot Item", 249: "Microsoft Classless Static Route", 252: "WPAD",
}

func dhcpOptionName(opt byte) string {
	if n, ok := dhcpOptionNames[opt]; ok {
		return n
	}
	return fmt.Sprintf("Option %d", opt)
}

func dhcpIP(b []byte) string {
	if len(b) == 4 {
		return netip.AddrFrom4([4]byte{b[0], b[1], b[2], b[3]}).String()
	}
	return ""
}

func dhcpIPList(b []byte) string {
	var out []string
	for i := 0; i+4 <= len(b); i += 4 {
		out = append(out, netip.AddrFrom4([4]byte{b[i], b[i+1], b[i+2], b[i+3]}).String())
	}
	return strings.Join(out, ", ")
}

func dhcpUintList(b []byte, width int) string {
	var out []string
	for i := 0; i+width <= len(b); i += width {
		switch width {
		case 1:
			out = append(out, strconv.Itoa(int(b[i])))
		case 2:
			out = append(out, strconv.Itoa(int(be16(b[i:i+2]))))
		case 4:
			out = append(out, strconv.FormatUint(uint64(be32(b[i:i+4])), 10))
		}
	}
	return strings.Join(out, ", ")
}

func dhcpDomainSearch(b []byte) string {
	var names []string
	for i := 0; i < len(b); {
		var labels []string
		for i < len(b) && b[i] != 0 {
			l := int(b[i])
			i++
			if i+l > len(b) {
				return strings.Join(names, ", ")
			}
			labels = append(labels, string(b[i:i+l]))
			i += l
		}
		if i < len(b) && b[i] == 0 {
			i++
		}
		if len(labels) > 0 {
			names = append(names, strings.Join(labels, "."))
		}
	}
	return strings.Join(names, ", ")
}

func dhcpClasslessRoutes(b []byte) string {
	var out []string
	for i := 0; i < len(b); {
		width := int(b[i])
		i++
		if width < 1 || width > 32 || i+1+(width+7)/8+4 > len(b) {
			break
		}
		prefix := int(b[i])
		i++
		n := int((prefix + 7) / 8)
		if i+n+4 > len(b) {
			break
		}
		var dst [4]byte
		copy(dst[:], b[i:i+n])
		i += n
		router := netip.AddrFrom4([4]byte{b[i], b[i+1], b[i+2], b[i+3]})
		i += 4
		out = append(out, fmt.Sprintf("%s/%d via %s", netip.AddrFrom4(dst), prefix, router))
		_ = width
	}
	return strings.Join(out, "; ")
}

func dhcpRelaySuboptions(b []byte) string {
	var out []string
	for i := 0; i+2 <= len(b); {
		code := b[i]
		l := int(b[i+1])
		i += 2
		if i+l > len(b) {
			break
		}
		v := b[i : i+l]
		switch code {
		case 1:
			out = append(out, "Circuit-ID="+hexPreview(v, 32))
		case 2:
			out = append(out, "Remote-ID="+hexPreview(v, 32))
		default:
			out = append(out, fmt.Sprintf("sub-option %d=%s", code, hexPreview(v, 16)))
		}
		i += l
	}
	return strings.Join(out, ", ")
}

func dhcpOptionText(opt byte, v []byte) string {
	switch opt {
	case 1, 28, 50, 54:
		return dhcpIP(v)
	case 3, 4, 5, 6, 7, 8, 9, 10, 11, 41, 42, 44, 45, 48, 49, 65, 68, 69, 70, 71, 72, 73, 74, 75, 76:
		return dhcpIPList(v)
	case 26, 57:
		return fmt.Sprintf("%d", be16(v))
	case 51, 58, 59, 91:
		return fmt.Sprintf("%d seconds", be32(v))
	case 2, 13, 22, 24, 35, 38:
		return dhcpUintList(v, 4)
	case 23, 37, 39:
		return dhcpUintList(v, 1)
	case 52:
		return fmt.Sprintf("%d", v[0])
	case 53:
		if len(v) > 0 {
			return dhcpTypeName(v[0])
		}
	case 55:
		var names []string
		for _, b := range v {
			names = append(names, dhcpOptionName(b))
		}
		return strings.Join(names, ", ")
	case 81:
		return hexPreview(v, 64)
	case 82:
		return dhcpRelaySuboptions(v)
	case 119:
		return dhcpDomainSearch(v)
	case 121, 249:
		return dhcpClasslessRoutes(v)
	case 12, 15, 56, 60, 66, 67, 252:
		return string(v)
	case 61:
		return hexPreview(v, 32)
	case 43, 125:
		return hexPreview(v, 64)
	}
	if len(v) == 4 {
		return dhcpIP(v)
	}
	return hexPreview(v, 48)
}

func (c *ctx) dissectDHCP(b []byte, base int) bool {
	if len(b) < 240 || (b[0] != 1 && b[0] != 2) {
		return false
	}
	msgType := uint8(0)
	hostname := ""
	requestedIP := ""

	c.addLayer("dhcp")
	c.proto = "dhcp"
	root := newNode("Dynamic Host Configuration Protocol", base, len(b))
	root.add(
		newField(fmt.Sprintf("Message type: %s", map[byte]string{1: "BOOTREQUEST", 2: "BOOTREPLY"}[b[0]]), "", base, 1),
		newField("Hardware type: "+arpHwName(be16(b[1:3])), "", base+1, 2),
		newField(fmt.Sprintf("Hardware address length: %d", b[2]), "", base+2, 1),
		newField(fmt.Sprintf("Hops: %d", b[3]), "", base+3, 1),
		newField(fmt.Sprintf("Transaction ID: 0x%08x", be32(b[4:8])), "", base+4, 4),
		newField(fmt.Sprintf("Seconds elapsed: %d", be16(b[8:10])), "", base+8, 2),
		newField(fmt.Sprintf("Flags: 0x%04x%s", be16(b[10:12]), func() string {
			if be16(b[10:12])&0x8000 != 0 {
				return " (broadcast)"
			}
			return ""
		}()), "", base+10, 2),
		newField("Client IP address: "+ip4String(be32(b[12:16])), "", base+12, 4),
		newField("Your (client) IP address: "+ip4String(be32(b[16:20])), "", base+16, 4),
		newField("Next server IP address: "+ip4String(be32(b[20:24])), "", base+20, 4),
		newField("Relay agent IP address: "+ip4String(be32(b[24:28])), "", base+24, 4),
		newField("Client MAC address: "+macString(b[28:34]), "", base+28, 6),
	)
	if s := trimNul(b[44:108]); s != "" {
		root.add(newField("Server host name: "+s, "", base+44, 64))
	}
	if f := trimNul(b[108:236]); f != "" {
		root.add(newField("Boot file name: "+f, "", base+108, 128))
	}
	magic := be32(b[236:240])
	root.add(newField(fmt.Sprintf("Magic Cookie: 0x%08x", magic), "", base+236, 4))

	var parseOptions func(opts []byte, optBase int, section string)
	parseOptions = func(opts []byte, optBase int, section string) {
		for off := 0; off < len(opts); {
			opt := opts[off]
			if opt == 255 {
				root.add(newField("End Option", "", optBase+off, 1))
				break
			}
			if opt == 0 {
				off++
				continue
			}
			if off+2 > len(opts) {
				break
			}
			l := int(opts[off+1])
			if off+2+l > len(opts) {
				break
			}
			v := opts[off+2 : off+2+l]
			val := dhcpOptionText(opt, v)
			label := fmt.Sprintf("%s: %s", dhcpOptionName(opt), val)
			if section != "" {
				label = section + ": " + label
			}
			root.add(newField(label, "", optBase+off, 2+l))
			switch opt {
			case 53:
				if len(v) > 0 {
					msgType = v[0]
				}
			case 12:
				hostname = string(v)
			case 50:
				requestedIP = dhcpIP(v)
			case 52:
				if len(v) > 0 && section == "" {
					if v[0]&1 != 0 {
						parseOptions(b[108:236], base+108, "bootfile")
					}
					if v[0]&2 != 0 {
						parseOptions(b[44:108], base+44, "sname")
					}
				}
			}
			off += 2 + l
		}
	}
	parseOptions(b[240:], base+240, "")

	root.Label = fmt.Sprintf("Dynamic Host Configuration Protocol (%s)", dhcpTypeName(msgType))
	c.addRoot(root)
	c.appInfo = dhcpTypeName(msgType)
	if hostname != "" {
		c.appInfo += " (" + hostname + ")"
	}
	if requestedIP != "" && msgType == 3 {
		c.appInfo += " requested=" + requestedIP
	}
	return true
}
