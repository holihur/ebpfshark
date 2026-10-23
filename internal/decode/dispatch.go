package decode

import "fmt"

func (c *ctx) dissectUDPPayload(b []byte, base int, sport, dport uint16) bool {
	if len(b) == 0 {
		return true
	}
	return runDissectors(c, b, base, sport, dport, appChain(TransportUDP))
}

func (c *ctx) dissectTCPPayload(b []byte, base int, sport, dport uint16) {
	if len(b) == 0 {
		return
	}
	if !looksLikeHTTP(b) && c.dissectAIHTTPContinuation(b, base) {
		return
	}
	if runDissectors(c, b, base, sport, dport, appChain(TransportTCP)) {
		return
	}
	c.addLayer("data")
	c.addRoot(c.newField(fmt.Sprintf("TCP payload (%d bytes)", len(b)), hexPreview(b, 64), base, len(b)))
}

func (c *ctx) dissectDecryptedApp(b []byte, base int) {
	runDissectors(c, b, base, 0, 0, decryptedChain())
}
