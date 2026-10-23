//go:build full

package decode

import "fmt"

func modbusFunctionName(fc byte) string {
	switch fc {
	case 1:
		return "Read Coils"
	case 2:
		return "Read Discrete Inputs"
	case 3:
		return "Read Holding Registers"
	case 4:
		return "Read Input Registers"
	case 5:
		return "Write Single Coil"
	case 6:
		return "Write Single Register"
	case 15:
		return "Write Multiple Coils"
	case 16:
		return "Write Multiple Registers"
	case 23:
		return "Read/Write Multiple Registers"
	case 43:
		return "Encapsulated Interface Transport"
	}
	return fmt.Sprintf("Function 0x%02x", fc)
}

func looksLikeModbus(b []byte) bool {
	if len(b) < 8 || b[2] != 0 || b[3] != 0 {
		return false
	}
	l := int(be16(b[4:6]))
	return l >= 2 && l <= len(b)-6
}

func (c *ctx) dissectModbus(b []byte, base int) bool {
	if !looksLikeModbus(b) {
		return false
	}
	tx := be16(b[0:2])
	length := int(be16(b[4:6]))
	unit := b[6]
	fc := b[7]
	c.addLayer("modbus")
	c.proto = "modbus"
	root := newNode("Modbus/TCP", base, min(len(b), 6+length))
	root.add(c.newField(fmt.Sprintf("Transaction ID: %d", tx), "", base, 2),
		c.newField("Protocol ID: 0", "", base+2, 2),
		c.newField(fmt.Sprintf("Length: %d", length), "", base+4, 2),
		c.newField(fmt.Sprintf("Unit ID: %d", unit), "", base+6, 1),
		c.newField(fmt.Sprintf("Function: %s (0x%02x)", modbusFunctionName(fc), fc), "", base+7, 1))
	pdu := b[8:]
	info := "Modbus " + modbusFunctionName(fc)
	switch fc {
	case 1, 2, 3, 4:
		if len(pdu) >= 4 {
			start, count := be16(pdu[0:2]), be16(pdu[2:4])
			root.add(c.newField(fmt.Sprintf("Start Address: %d", start), "", base+8, 2),
				c.newField(fmt.Sprintf("Quantity: %d", count), "", base+10, 2))
			info += fmt.Sprintf(" addr=%d count=%d", start, count)
		}
		// Response: byte count followed by values.
		if len(pdu) >= 2 && pdu[0] == byte(len(pdu)-1) {
			root.add(c.newField(fmt.Sprintf("Byte Count: %d", pdu[0]), "", base+8, 1))
			if fc == 3 || fc == 4 {
				var vals []string
				for i := 1; i+1 < len(pdu) && len(vals) < 32; i += 2 {
					vals = append(vals, fmt.Sprintf("%d", be16(pdu[i:i+2])))
				}
				if len(vals) > 0 {
					root.add(c.newField("Registers: "+joinComma(vals), "", base+9, len(vals)*2))
				}
			}
		}
	case 5:
		if len(pdu) >= 4 {
			addr, val := be16(pdu[0:2]), be16(pdu[2:4])
			root.add(c.newField(fmt.Sprintf("Output Address: %d", addr), "", base+8, 2),
				c.newField(fmt.Sprintf("Output Value: 0x%04x", val), "", base+10, 2))
			info += fmt.Sprintf(" addr=%d value=0x%04x", addr, val)
		}
	case 6:
		if len(pdu) >= 4 {
			addr, val := be16(pdu[0:2]), be16(pdu[2:4])
			root.add(c.newField(fmt.Sprintf("Register Address: %d", addr), "", base+8, 2),
				c.newField(fmt.Sprintf("Register Value: %d", val), "", base+10, 2))
			info += fmt.Sprintf(" addr=%d value=%d", addr, val)
		}
	case 15, 16:
		if len(pdu) >= 5 {
			addr, count := be16(pdu[0:2]), be16(pdu[2:4])
			root.add(c.newField(fmt.Sprintf("Start Address: %d", addr), "", base+8, 2),
				c.newField(fmt.Sprintf("Quantity: %d", count), "", base+10, 2),
				c.newField(fmt.Sprintf("Byte Count: %d", pdu[4]), "", base+12, 1))
			info += fmt.Sprintf(" addr=%d count=%d", addr, count)
		}
	}
	if len(pdu) > 0 && fc&0x80 != 0 {
		root.add(c.newField(fmt.Sprintf("Exception Code: %d", pdu[len(pdu)-1]), "", base+8, 1))
		info += " exception"
	}
	c.addRoot(root)
	c.appInfo = shorten(info, 160)
	return true
}

func joinComma(v []string) string {
	out := ""
	for i, s := range v {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}

func init() {
	RegisterPlugin(pluginSpec{Name: "modbus", Priority: 120, Transport: TransportTCP,
		Match: func(_ *ctx, sport, dport uint16, b []byte) bool {
			return (sport == 502 || dport == 502) && looksLikeModbus(b)
		}, Dissect: func(c *ctx, b []byte, base int) bool { return c.dissectModbus(b, base) }, Display: "Modbus"})
}
