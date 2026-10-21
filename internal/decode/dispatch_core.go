//go:build !full

package decode

import "fmt"

func coreUDPChain() []appDissector {
	return []appDissector{
		{"dns", portMatch(dnsPorts), func(c *ctx, b []byte, base int) bool { return c.dissectDNS(b, base, false) }},
		{"dhcp", func(_ *ctx, sport, dport uint16, _ []byte) bool { return isDHCP(sport, dport) }, func(c *ctx, b []byte, base int) bool { return c.dissectDHCP(b, base) }},
	}
}

func coreTCPChain() []appDissector {
	return []appDissector{
		{"dns", portMatch(dnsPorts), func(c *ctx, b []byte, base int) bool { return c.dissectDNS(b, base, true) }},
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
	return runDissectors(c, b, base, sport, dport, coreUDPChain())
}

func (c *ctx) dissectTCPPayload(b []byte, base int, sport, dport uint16) {
	if len(b) == 0 {
		return
	}
	if runDissectors(c, b, base, sport, dport, coreTCPChain()) {
		return
	}
	c.addLayer("data")
	c.addRoot(newField(fmt.Sprintf("TCP payload (%d bytes)", len(b)), hexPreview(b, 64), base, len(b)))
}

func (c *ctx) dissectDecryptedApp(b []byte, base int) {
	if bytesHasPrefixFold(b, "GET ") || bytesHasPrefixFold(b, "POST ") || bytesHasPrefixFold(b, "HTTP/") {
		c.dissectHTTP(b, base)
	}
}
