//go:build full

package filter

// protocolLayerNames lists every protocol available in the full build.
func protocolLayerNames() []string {
	return []string{
		"ip", "ipv6", "tcp", "udp", "icmp", "icmpv6", "arp", "dns", "http", "http2",
		"tls", "dhcp", "vlan", "eth", "vxlan", "mpls", "gre", "igmp", "quic", "ntp",
		"snmp", "syslog", "stun", "mqtt", "redis", "postgresql", "mysql", "bgp", "ssh", "ssdp",
		"sip", "radius", "netflow", "rtp", "rtcp", "coap", "modbus", "mqttsn", "rtsp", "mpegts", "h264", "h265", "vp8", "vp9", "av1", "aac", "opus", "amqp", "bacnet", "opcua", "lorawan", "hls", "grpc", "protobuf", "websocket", "wireguard",
	}
}
