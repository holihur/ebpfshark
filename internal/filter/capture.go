package filter

import "net/netip"

// CaptureSpec is the conservative L2-L4 subset of a display filter that can be
// pushed into the eBPF capture path. It must never drop a packet that could
// match the original display filter; application fields and complex boolean
// expressions stay in user space.
type CaptureSpec struct {
	Proto     uint8      `json:"proto,omitempty"`
	IPVersion uint8      `json:"ipVersion,omitempty"`
	SrcPortLo uint16     `json:"srcPortLo,omitempty"`
	SrcPortHi uint16     `json:"srcPortHi,omitempty"`
	DstPortLo uint16     `json:"dstPortLo,omitempty"`
	DstPortHi uint16     `json:"dstPortHi,omitempty"`
	VLAN      uint16     `json:"vlan,omitempty"`
	HasVLAN   bool       `json:"hasVLAN,omitempty"`
	SrcIPv4   netip.Addr `json:"srcIPv4,omitempty"`
	SrcMask   uint8      `json:"srcMask,omitempty"`
	DstIPv4   netip.Addr `json:"dstIPv4,omitempty"`
	DstMask   uint8      `json:"dstMask,omitempty"`
}

func (s CaptureSpec) Empty() bool {
	return s.Proto == 0 && s.IPVersion == 0 && !s.HasVLAN &&
		s.SrcPortLo == 0 && s.SrcPortHi == 0 && s.DstPortLo == 0 && s.DstPortHi == 0 &&
		!s.SrcIPv4.IsValid() && !s.DstIPv4.IsValid()
}

// CompileCapture parses a display filter and extracts the safe kernel subset.
func CompileCapture(input string) (CaptureSpec, error) {
	f, err := Parse(input)
	if err != nil {
		return CaptureSpec{}, err
	}
	return ExtractCapture(f), nil
}

// ExtractCapture derives a conservative AND-only capture filter.
func ExtractCapture(f Filter) CaptureSpec {
	switch n := f.(type) {
	case andNode:
		return mergeCapture(ExtractCapture(n.l), ExtractCapture(n.r))
	case orNode:
		a, b := ExtractCapture(n.l), ExtractCapture(n.r)
		if a == b {
			return a
		}
		return CaptureSpec{}
	case notNode:
		return CaptureSpec{}
	case layerNode:
		return layerCapture(n.name)
	case portNode:
		s := CaptureSpec{}
		if n.dir != 2 {
			s.SrcPortLo, s.SrcPortHi = n.lo, n.hi
		}
		if n.dir != 1 {
			s.DstPortLo, s.DstPortHi = n.lo, n.hi
		}
		return s
	case hostNode:
		if n.prefix.Addr().Is4() && n.prefix.Bits() >= 0 && n.prefix.Bits() <= 32 {
			s := CaptureSpec{}
			if n.dir != 2 {
				s.SrcIPv4, s.SrcMask = n.prefix.Addr(), uint8(n.prefix.Bits())
			}
			if n.dir != 1 {
				s.DstIPv4, s.DstMask = n.prefix.Addr(), uint8(n.prefix.Bits())
			}
			return s
		}
		return CaptureSpec{}
	case cmpNode:
		return cmpCapture(n)
	}
	return CaptureSpec{}
}

func layerCapture(name string) CaptureSpec {
	s := CaptureSpec{}
	switch name {
	case "tcp":
		s.Proto = 6
	case "udp":
		s.Proto = 17
	case "icmp":
		s.Proto = 1
	case "icmpv6", "icmp6":
		s.Proto = 58
	case "ip":
		s.IPVersion = 4
	case "ipv6", "ip6":
		s.IPVersion = 6
	case "vlan":
		s.HasVLAN, s.VLAN = true, 0xffff
	}
	return s
}

func cmpCapture(n cmpNode) CaptureSpec {
	s := CaptureSpec{}
	switch n.field {
	case "ip.proto", "ip.protocol":
		if n.op == "==" && n.num <= 255 {
			s.Proto = uint8(n.num)
		}
	case "ip.src", "ipv6.src", "ip6.src":
		if n.op == "==" && n.addr.Addr().Is4() && n.addr.Bits() >= 0 && n.addr.Bits() <= 32 {
			s.SrcIPv4, s.SrcMask = n.addr.Addr(), uint8(n.addr.Bits())
		}
	case "ip.dst", "ipv6.dst", "ip6.dst":
		if n.op == "==" && n.addr.Addr().Is4() && n.addr.Bits() >= 0 && n.addr.Bits() <= 32 {
			s.DstIPv4, s.DstMask = n.addr.Addr(), uint8(n.addr.Bits())
		}
	case "ip.addr", "ipv6.addr", "ip6.addr":
		if n.op == "==" && n.addr.Addr().Is4() && n.addr.Bits() >= 0 && n.addr.Bits() <= 32 {
			s.SrcIPv4, s.SrcMask = n.addr.Addr(), uint8(n.addr.Bits())
			s.DstIPv4, s.DstMask = n.addr.Addr(), uint8(n.addr.Bits())
		}
	case "tcp.srcport", "udp.srcport":
		if n.op == "==" && n.num <= 65535 {
			s.SrcPortLo, s.SrcPortHi = uint16(n.num), uint16(n.num)
		}
	case "tcp.dstport", "udp.dstport":
		if n.op == "==" && n.num <= 65535 {
			s.DstPortLo, s.DstPortHi = uint16(n.num), uint16(n.num)
		}
	case "tcp.port", "udp.port":
		if n.op == "==" && n.num <= 65535 {
			s.SrcPortLo, s.SrcPortHi = uint16(n.num), uint16(n.num)
			s.DstPortLo, s.DstPortHi = uint16(n.num), uint16(n.num)
		}
	case "vlan.id":
		if n.op == "==" && n.num <= 4095 {
			s.VLAN, s.HasVLAN = uint16(n.num), true
		}
	}
	return s
}

func mergeCapture(a, b CaptureSpec) CaptureSpec {
	out := a
	if out.Proto == 0 {
		out.Proto = b.Proto
	} else if b.Proto != 0 && b.Proto != out.Proto {
		out.Proto = 0
	}
	if out.IPVersion == 0 {
		out.IPVersion = b.IPVersion
	} else if b.IPVersion != 0 && b.IPVersion != out.IPVersion {
		out.IPVersion = 0
	}
	if !out.HasVLAN && b.HasVLAN {
		out.VLAN, out.HasVLAN = b.VLAN, true
	} else if out.HasVLAN && b.HasVLAN && out.VLAN != b.VLAN {
		out.HasVLAN, out.VLAN = false, 0
	}
	if !out.SrcIPv4.IsValid() {
		out.SrcIPv4, out.SrcMask = b.SrcIPv4, b.SrcMask
	} else if b.SrcIPv4.IsValid() && (b.SrcIPv4 != out.SrcIPv4 || b.SrcMask != out.SrcMask) {
		out.SrcIPv4, out.SrcMask = netip.Addr{}, 0
	}
	if !out.DstIPv4.IsValid() {
		out.DstIPv4, out.DstMask = b.DstIPv4, b.DstMask
	} else if b.DstIPv4.IsValid() && (b.DstIPv4 != out.DstIPv4 || b.DstMask != out.DstMask) {
		out.DstIPv4, out.DstMask = netip.Addr{}, 0
	}
	out.SrcPortLo, out.SrcPortHi = mergeRange(out.SrcPortLo, out.SrcPortHi, b.SrcPortLo, b.SrcPortHi)
	out.DstPortLo, out.DstPortHi = mergeRange(out.DstPortLo, out.DstPortHi, b.DstPortLo, b.DstPortHi)
	return out
}

func mergeRange(alo, ahi, blo, bhi uint16) (uint16, uint16) {
	if alo == 0 && ahi == 0 {
		return blo, bhi
	}
	if blo == 0 && bhi == 0 {
		return alo, ahi
	}
	if alo > bhi || blo > ahi {
		return 0, 0
	}
	if blo > alo {
		alo = blo
	}
	if bhi < ahi {
		ahi = bhi
	}
	return alo, ahi
}
