package decode

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

func init() {
	RegisterPlugin(pluginSpec{Name: "dhcp", Priority: 20, Transport: TransportUDP,
		Match:   func(_ *ctx, sport, dport uint16, _ []byte) bool { return isDHCP(sport, dport) },
		Dissect: func(c *ctx, b []byte, base int) bool { return c.dissectDHCP(b, base) }})
}
