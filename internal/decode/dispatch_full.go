//go:build full

package decode

import "fmt"

func fullUDPChain() []appDissector {
	return []appDissector{
		{"dns", portMatch(dnsPorts), func(c *ctx, b []byte, base int) bool { return c.dissectDNS(b, base, false) }},
		{"dhcp", func(_ *ctx, sport, dport uint16, _ []byte) bool { return isDHCP(sport, dport) }, func(c *ctx, b []byte, base int) bool { return c.dissectDHCP(b, base) }},
		{"ntp", portMatch(map[uint16]bool{123: true}), func(c *ctx, b []byte, base int) bool { return c.dissectNTP(b, base) }},
		{"snmp", portMatch(map[uint16]bool{161: true, 162: true}), func(c *ctx, b []byte, base int) bool { return c.dissectSNMP(b, base) }},
		{"syslog", portMatch(map[uint16]bool{514: true}), func(c *ctx, b []byte, base int) bool { return c.dissectSyslog(b, base) }},
		{"stun", portMatch(map[uint16]bool{3478: true, 3479: true}), func(c *ctx, b []byte, base int) bool { return c.dissectSTUN(b, base) }},
		{"vxlan", portMatch(map[uint16]bool{4789: true, 8472: true}), func(c *ctx, b []byte, base int) bool { return c.dissectVXLAN(b, base) }},
		{"wireguard", portMatch(map[uint16]bool{51820: true}), func(c *ctx, b []byte, base int) bool { return c.dissectWireGuard(b, base) }},
		{"ssdp", portMatch(map[uint16]bool{1900: true}), func(c *ctx, b []byte, base int) bool { return c.dissectSSDP(b, base) }},
		{"sip", portMatch(map[uint16]bool{5060: true}), func(c *ctx, b []byte, base int) bool { return c.dissectSIP(b, base) }},
		{"radius", portMatch(map[uint16]bool{1812: true, 1813: true, 1645: true, 1646: true}), func(c *ctx, b []byte, base int) bool { return c.dissectRADIUS(b, base) }},
		{"netflow", portMatch(map[uint16]bool{2055: true, 2056: true, 4739: true, 9995: true, 6343: true}), func(c *ctx, b []byte, base int) bool { return c.dissectNetFlow(b, base) }},
		{"rtp", func(_ *ctx, sport, dport uint16, b []byte) bool {
			return (sport == 5004 || dport == 5004 || sport == 5005 || dport == 5005) && looksLikeRTP(b)
		}, func(c *ctx, b []byte, base int) bool { return c.dissectRTP(b, base) }},
		{"quic", func(_ *ctx, sport, dport uint16, b []byte) bool {
			return (sport == 443 || dport == 443) && looksLikeQUIC(b)
		}, func(c *ctx, b []byte, base int) bool { return c.dissectQUIC(b, base) }},
	}
}

func fullTCPChain() []appDissector {
	return []appDissector{
		{"dns", portMatch(dnsPorts), func(c *ctx, b []byte, base int) bool { return c.dissectDNS(b, base, true) }},
		{"http2", func(_ *ctx, sport, dport uint16, b []byte) bool {
			return looksLikeHTTP2(b) || ((httpPorts[sport] || httpPorts[dport]) && looksLikeHTTP2Frame(b))
		}, func(c *ctx, b []byte, base int) bool { return c.dissectHTTP2(b, base) }},
		{"ssh", func(_ *ctx, _ uint16, _ uint16, b []byte) bool { return looksLikeSSHBanner(b) }, func(c *ctx, b []byte, base int) bool { return c.dissectSSH(b, base) }},
		{"redis", portMatch(map[uint16]bool{6379: true}), func(c *ctx, b []byte, base int) bool { return c.dissectRedis(b, base) }},
		{"postgresql", portMatch(map[uint16]bool{5432: true}), func(c *ctx, b []byte, base int) bool { return c.dissectPostgreSQL(b, base) }},
		{"mysql", portMatch(map[uint16]bool{3306: true}), func(c *ctx, b []byte, base int) bool { return c.dissectMySQL(b, base) }},
		{"mqtt", portMatch(map[uint16]bool{1883: true}), func(c *ctx, b []byte, base int) bool { return c.dissectMQTT(b, base) }},
		{"bgp", portMatch(map[uint16]bool{179: true}), func(c *ctx, b []byte, base int) bool { return c.dissectBGP(b, base) }},
		{"ssh-port", portMatch(map[uint16]bool{22: true}), func(c *ctx, b []byte, base int) bool { return c.dissectSSH(b, base) }},
		{"sip", portMatch(map[uint16]bool{5060: true}), func(c *ctx, b []byte, base int) bool { return c.dissectSIP(b, base) }},
		{"radius", portMatch(map[uint16]bool{1812: true, 1813: true, 1645: true, 1646: true}), func(c *ctx, b []byte, base int) bool { return c.dissectRADIUS(b, base) }},
		{"netflow", portMatch(map[uint16]bool{2055: true, 2056: true, 4739: true, 9995: true, 6343: true}), func(c *ctx, b []byte, base int) bool { return c.dissectNetFlow(b, base) }},
		{"rtp", func(_ *ctx, sport, dport uint16, b []byte) bool {
			return (sport == 5004 || dport == 5004 || sport == 5005 || dport == 5005) && looksLikeRTP(b)
		}, func(c *ctx, b []byte, base int) bool { return c.dissectRTP(b, base) }},
		{"syslog", portMatch(map[uint16]bool{514: true}), func(c *ctx, b []byte, base int) bool { return c.dissectSyslog(b, base) }},
		{"websocket", func(_ *ctx, sport, dport uint16, b []byte) bool {
			return (httpPorts[sport] || httpPorts[dport] || tlsPorts[sport] || tlsPorts[dport]) && looksLikeWebSocketFrame(b)
		}, func(c *ctx, b []byte, base int) bool { return c.dissectWebSocket(b, base) }},
		{"http", func(_ *ctx, sport, dport uint16, b []byte) bool {
			return httpPorts[sport] || httpPorts[dport] || looksLikeHTTP(b)
		}, func(c *ctx, b []byte, base int) bool { return c.dissectHTTP(b, base) }},
		{"tls", func(_ *ctx, sport, dport uint16, b []byte) bool {
			return tlsPorts[sport] || tlsPorts[dport] || looksLikeTLS(b)
		}, func(c *ctx, b []byte, base int) bool { return c.dissectTLS(b, base) }},
	}
}

func (c *ctx) dissectUDPPayload(b []byte, base int, sport, dport uint16) bool {
	if len(b) == 0 {
		return true
	}
	return runDissectors(c, b, base, sport, dport, fullUDPChain())
}

func (c *ctx) dissectTCPPayload(b []byte, base int, sport, dport uint16) {
	if len(b) == 0 {
		return
	}
	if runDissectors(c, b, base, sport, dport, fullTCPChain()) {
		return
	}
	c.addLayer("data")
	c.addRoot(c.newField(fmt.Sprintf("TCP payload (%d bytes)", len(b)), hexPreview(b, 64), base, len(b)))
}

func (c *ctx) dissectDecryptedApp(b []byte, base int) {
	if looksLikeWebSocketFrame(b) {
		c.dissectWebSocket(b, base)
		return
	}
	if bytesHasPrefixFold(b, "PRI * HTTP/2.0") || looksLikeHTTP2Frame(b) {
		c.dissectHTTP2(b, base)
		return
	}
	if bytesHasPrefixFold(b, "GET ") || bytesHasPrefixFold(b, "POST ") || bytesHasPrefixFold(b, "HTTP/") {
		c.dissectHTTP(b, base)
	}
}
