//go:build full

package decode

import (
	"fmt"
	"time"
)

// ------------------------------------------------------------------- NTP

var ntpModes = []string{"reserved", "symmetric active", "symmetric passive", "client", "server", "broadcast", "control", "private"}

func ntpMode(mode uint8) string {
	if int(mode) < len(ntpModes) {
		return ntpModes[mode]
	}
	return fmt.Sprintf("mode %d", mode)
}

func ntpTimestamp(b []byte) string {
	if len(b) < 8 {
		return "0"
	}
	sec := be32(b[0:4])
	frac := be32(b[4:8])
	if sec == 0 && frac == 0 {
		return "0"
	}
	unix := int64(sec) - 2208988800
	ns := int64(float64(frac) / 4294967296.0 * 1e9)
	return time.Unix(unix, ns).UTC().Format("2006-01-02 15:04:05.000000 MST")
}

func (c *ctx) dissectNTP(b []byte, base int) bool {
	if len(b) < 48 {
		return false
	}
	vn := (b[0] >> 3) & 0x7
	if vn < 1 || vn > 4 {
		return false
	}
	li := b[0] >> 6
	mode := b[0] & 0x7
	stratum := b[1]
	poll := int8(b[2])
	precision := int8(b[3])

	c.addLayer("ntp")
	c.proto = "ntp"
	root := c.newNode(fmt.Sprintf("Network Time Protocol (%s, v%d)", ntpMode(mode), vn), base, len(b))
	root.add(
		c.newField(fmt.Sprintf("Leap Indicator: %d", li), "", base, 1),
		c.newField(fmt.Sprintf("Version: %d", vn), "", base, 1),
		c.newField(fmt.Sprintf("Mode: %d (%s)", mode, ntpMode(mode)), "", base, 1),
		c.newField(fmt.Sprintf("Stratum: %d", stratum), "", base+1, 1),
		c.newField(fmt.Sprintf("Poll: %d seconds", poll), "", base+2, 1),
		c.newField(fmt.Sprintf("Precision: %d", precision), "", base+3, 1),
		c.newField(fmt.Sprintf("Root Delay: %.6f s", float64(be32(b[4:8]))/65536), "", base+4, 4),
		c.newField(fmt.Sprintf("Root Dispersion: %.6f s", float64(be32(b[8:12]))/65536), "", base+8, 4),
		c.newField(fmt.Sprintf("Reference ID: 0x%08x", be32(b[12:16])), "", base+12, 4),
		c.newField("Reference Timestamp: "+ntpTimestamp(b[16:24]), "", base+16, 8),
		c.newField("Origin Timestamp: "+ntpTimestamp(b[24:32]), "", base+24, 8),
		c.newField("Receive Timestamp: "+ntpTimestamp(b[32:40]), "", base+32, 8),
		c.newField("Transmit Timestamp: "+ntpTimestamp(b[40:48]), "", base+40, 8),
	)
	if len(b) > 48 {
		ext := c.newNode(fmt.Sprintf("Extension Fields / MAC (%d bytes)", len(b)-48), base+48, len(b)-48)
		off := 48
		for off+4 <= len(b) {
			etype := be16(b[off : off+2])
			elen := int(be16(b[off+2 : off+4]))
			if elen < 4 || off+elen > len(b) {
				break
			}
			name := "Extension Field"
			switch etype {
			case 0x0104:
				name = "RATE"
			case 0x0204:
				name = "AUTOKEY"
			case 0x2005:
				name = "NTS Cookie"
			case 0x2006:
				name = "NTS Cookie Placeholder"
			case 0x2007:
				name = "NTS Authenticator and Encrypted Extension Fields"
			}
			ext.add(c.newField(fmt.Sprintf("%s (type 0x%04x, %d bytes)", name, etype, elen), hexPreview(b[off+4:off+elen], 48), base+off, elen))
			off += (elen + 3) &^ 3
		}
		if off < len(b) {
			ext.add(c.newField(fmt.Sprintf("MAC / trailing data (%d bytes)", len(b)-off), hexPreview(b[off:], 48), base+off, len(b)-off))
		}
		if len(ext.Children) > 0 {
			root.add(ext)
		}
	}
	c.addRoot(root)

	switch mode {
	case 3:
		c.appInfo = fmt.Sprintf("NTP client v%d", vn)
	case 4:
		c.appInfo = fmt.Sprintf("NTP server v%d, stratum %d", vn, stratum)
	case 1, 2:
		c.appInfo = fmt.Sprintf("NTP %s v%d", ntpMode(mode), vn)
	default:
		c.appInfo = fmt.Sprintf("NTP %s v%d", ntpMode(mode), vn)
	}
	return true
}

func init() {
	RegisterPlugin(pluginSpec{Name: "ntp", Priority: 30, Transport: TransportUDP,
		Match: portMatch(map[uint16]bool{123: true}), Dissect: func(c *ctx, b []byte, base int) bool { return c.dissectNTP(b, base) }})
}
