//go:build full

package decode

import "fmt"

// ------------------------------------------------------------- WireGuard

func (c *ctx) dissectWireGuard(b []byte, base int) bool {
	if len(b) < 4 {
		return false
	}
	typ := b[0]
	if typ < 1 || typ > 4 {
		return false
	}
	if b[1] != 0 || b[2] != 0 || b[3] != 0 {
		return false
	}
	names := []string{"", "handshake initiation", "handshake response", "cookie reply", "transport data"}
	c.addLayer("wireguard")
	c.proto = "wireguard"
	root := c.newNode("WireGuard ("+names[typ]+")", base, len(b))
	root.add(
		c.newField(fmt.Sprintf("Message Type: %d (%s)", typ, names[typ]), "", base, 1),
		c.newField("Reserved: 0", "", base+1, 3),
	)
	switch typ {
	case 1: // handshake initiation
		if len(b) >= 148 {
			root.add(
				c.newField(fmt.Sprintf("Sender Index: 0x%08x", be32(b[4:8])), "", base+4, 4),
				c.newField("Unencrypted Ephemeral: "+hexPreview(b[8:40], 32), "", base+8, 32),
				c.newField("Encrypted Static: "+hexPreview(b[40:88], 48), "", base+40, 48),
				c.newField("Encrypted Timestamp: "+hexPreview(b[88:116], 28), "", base+88, 28),
				c.newField("MAC1: "+hexPreview(b[116:132], 16), "", base+116, 16),
				c.newField("MAC2: "+hexPreview(b[132:148], 16), "", base+132, 16),
			)
		}
	case 2: // handshake response
		if len(b) >= 92 {
			root.add(
				c.newField(fmt.Sprintf("Sender Index: 0x%08x", be32(b[4:8])), "", base+4, 4),
				c.newField(fmt.Sprintf("Receiver Index: 0x%08x", be32(b[8:12])), "", base+8, 4),
				c.newField("Unencrypted Ephemeral: "+hexPreview(b[12:44], 32), "", base+12, 32),
				c.newField("Encrypted Nothing: "+hexPreview(b[44:60], 16), "", base+44, 16),
				c.newField("MAC1: "+hexPreview(b[60:76], 16), "", base+60, 16),
				c.newField("MAC2: "+hexPreview(b[76:92], 16), "", base+76, 16),
			)
		}
	case 3: // cookie reply
		if len(b) >= 64 {
			root.add(
				c.newField(fmt.Sprintf("Receiver Index: 0x%08x", be32(b[4:8])), "", base+4, 4),
				c.newField("Nonce: "+hexPreview(b[8:32], 24), "", base+8, 24),
				c.newField("Encrypted Cookie: "+hexPreview(b[32:64], 32), "", base+32, 32),
			)
		}
	case 4: // transport data
		if len(b) >= 16 {
			root.add(
				c.newField(fmt.Sprintf("Receiver Index: 0x%08x", be32(b[4:8])), "", base+4, 4),
				c.newField(fmt.Sprintf("Counter: %d", be64(b[8:16])), "", base+8, 8),
				c.newField(fmt.Sprintf("Encrypted Payload (%d bytes)", len(b)-16), hexPreview(b[16:], 48), base+16, len(b)-16),
			)
		}
	}
	c.addRoot(root)
	c.appInfo = "WireGuard " + names[typ]
	return true
}

func init() {
	RegisterPlugin(pluginSpec{Name: "wireguard", Priority: 80, Transport: TransportUDP,
		Match: portMatch(map[uint16]bool{51820: true}), Dissect: func(c *ctx, b []byte, base int) bool { return c.dissectWireGuard(b, base) }})
}
