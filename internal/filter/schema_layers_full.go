//go:build full

package filter

// protocolLayerNames lists every protocol available in the full build.
func protocolLayerNames() []string {
	return []string{
		"ip", "ipv6", "tcp", "udp", "icmp", "icmpv6", "arp", "dns", "http", "http2",
		"tls", "dhcp", "vlan", "eth", "vxlan", "mpls", "gre", "igmp", "quic", "ntp",
		"snmp", "syslog", "stun", "mqtt", "redis", "postgresql", "bgp", "ssh", "ssdp",
		"sip", "wireguard",
	}
}
