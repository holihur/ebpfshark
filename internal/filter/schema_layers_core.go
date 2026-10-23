//go:build !full

package filter

// protocolLayerNames lists protocols compiled into the core build.
func protocolLayerNames() []string {
	return []string{
		"ip", "ipv6", "tcp", "udp", "sctp", "wifi", "radiotap", "eapol", "hls", "icmp", "icmpv6", "arp", "dns", "http", "tls",
		"dhcp", "vlan", "eth", "mpls", "gre", "igmp",
	}
}
