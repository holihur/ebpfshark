//go:build full

package decode

import "fmt"

var bacnetServices = map[byte]string{
	0: "AcknowledgeAlarm", 1: "ConfirmedCOVNotification", 2: "ConfirmedEventNotification",
	3: "GetAlarmSummary", 4: "GetEnrollmentSummary", 5: "SubscribeCOV", 6: "AtomicReadFile",
	7: "AtomicWriteFile", 8: "AddListElement", 9: "RemoveListElement", 10: "CreateObject",
	11: "DeleteObject", 12: "ReadProperty", 13: "ReadPropertyConditional",
	14: "ReadPropertyMultiple", 15: "WriteProperty", 16: "WritePropertyMultiple",
	17: "DeviceCommunicationControl", 18: "ConfirmedPrivateTransfer", 19: "ConfirmedTextMessage",
	20: "ReinitializeDevice", 21: "VtOpen", 22: "VtClose", 23: "VtData",
	24: "Authenticate", 25: "RequestKey", 26: "ReadRange", 27: "LifeSafetyOperation",
	28: "SubscribeCOVProperty", 29: "GetEventInformation", 30: "SubscribeCOVPropertyMultiple",
	31: "ConfirmedCOVNotificationMultiple", 32: "ConfirmedAuditNotification",
	33: "AuditLogQuery", 34: "AckAlarm", 35: "WhoHas", 36: "WhoIs",
}

func bacnetAPDUType(t byte) string {
	switch t {
	case 0:
		return "Confirmed Request"
	case 1:
		return "Unconfirmed Request"
	case 2:
		return "Simple ACK"
	case 3:
		return "Complex ACK"
	case 5:
		return "Error"
	case 6:
		return "Reject"
	case 7:
		return "Abort"
	}
	return fmt.Sprintf("APDU type %d", t)
}

func looksLikeBACnet(b []byte) bool {
	return len(b) >= 6 && b[0] == 0x81 && (b[1] == 0x0a || b[1] == 0x0b || b[1] == 0x04 || b[1] == 0x05)
}

func (c *ctx) dissectBACnet(b []byte, base int) bool {
	if !looksLikeBACnet(b) {
		return false
	}
	blen := int(be16(b[2:4]))
	if blen < 6 || blen > len(b) {
		blen = len(b)
	}
	c.addLayer("bacnet")
	c.proto = "bacnet"
	root := newNode("BACnet/IP", base, blen)
	root.add(c.newField(fmt.Sprintf("BVLC Type: 0x%02x", b[0]), "", base, 1),
		c.newField(fmt.Sprintf("BVLC Function: 0x%02x", b[1]), "", base+1, 1),
		c.newField(fmt.Sprintf("BVLC Length: %d", be16(b[2:4])), "", base+2, 2))
	off := 4
	if off >= len(b) {
		c.addRoot(root)
		c.appInfo = "BACnet/IP"
		return true
	}
	root.add(c.newField(fmt.Sprintf("NPDU Version: %d", b[off]), "", base+off, 1))
	control := b[off+1]
	off += 2
	if control&0x20 != 0 && off+3 <= len(b) { // DNET/DLEN/DADR
		dlen := int(b[off+2])
		off += 3 + dlen
	}
	if control&0x08 != 0 && off+3 <= len(b) { // SNET/SLEN/SADR
		slen := int(b[off+2])
		off += 3 + slen
	}
	if control&0x20 != 0 {
		off++
	} // hop count
	info := "BACnet/IP"
	if off < len(b) {
		apduType := b[off] >> 4
		root.add(c.newField("APDU Type: "+bacnetAPDUType(apduType), "", base+off, 1))
		if apduType == 0 && off+3 <= len(b) {
			root.add(c.newField(fmt.Sprintf("Invoke ID: %d", b[off+2]), "", base+off+2, 1))
			if off+3 < len(b) {
				svc := b[off+3]
				name := bacnetServices[svc]
				if name == "" {
					name = fmt.Sprintf("service %d", svc)
				}
				root.add(c.newField("Service: "+name, "", base+off+3, 1))
				info += " " + name
			}
		} else if apduType == 1 && off+1 < len(b) {
			svc := b[off+1]
			name := bacnetServices[svc]
			if name == "" {
				name = fmt.Sprintf("service %d", svc)
			}
			root.add(c.newField("Service: "+name, "", base+off+1, 1))
			info += " " + name
		}
	}
	c.addRoot(root)
	c.appInfo = info
	return true
}

func init() {
	RegisterPlugin(pluginSpec{Name: "bacnet", Priority: 115, Transport: TransportUDP,
		Match: func(_ *ctx, sport, dport uint16, b []byte) bool {
			return (sport == 47808 || dport == 47808) && looksLikeBACnet(b)
		}, Dissect: func(c *ctx, b []byte, base int) bool { return c.dissectBACnet(b, base) }, Display: "BACnet"})
}
