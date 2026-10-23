//go:build full

package decode

import (
	"bytes"
	"fmt"
)

var amqpMethods = map[uint32]string{
	0x000a000a: "connection.start", 0x000a000b: "connection.start-ok",
	0x000a0014: "connection.secure", 0x000a001e: "connection.tune",
	0x000a001f: "connection.tune-ok", 0x000a0028: "connection.open",
	0x000a0029: "connection.open-ok", 0x000a0032: "connection.close",
	0x000a0033: "connection.close-ok",
	0x0014000a: "channel.open", 0x0014000b: "channel.open-ok",
	0x00140014: "channel.flow", 0x00140028: "channel.close", 0x00140029: "channel.close-ok",
	0x0028000a: "exchange.declare", 0x00280014: "exchange.delete",
	0x0028001e: "exchange.bind", 0x00280028: "exchange.unbind",
	0x0032000a: "queue.declare", 0x00320014: "queue.bind", 0x0032001e: "queue.purge",
	0x00320028: "queue.delete", 0x0032002a: "queue.unbind",
	0x003c000a: "basic.qos", 0x003c0014: "basic.consume", 0x003c001e: "basic.cancel",
	0x003c0028: "basic.publish", 0x003c003c: "basic.deliver", 0x003c0046: "basic.get",
	0x003c0050: "basic.ack", 0x003c005a: "basic.reject", 0x003c0078: "basic.nack",
	0x0055000a: "confirm.select",
}

func looksLikeAMQP(b []byte) bool {
	if len(b) >= 8 && bytes.Equal(b[:4], []byte("AMQP")) {
		return true
	}
	if len(b) < 8 || b[0] < 1 || b[0] > 8 {
		return false
	}
	size := int(be32(b[3:7]))
	return size >= 0 && 7+size < len(b) && b[7+size] == 0xce
}

func amqpShortString(b []byte, off int) (string, int, bool) {
	if off >= len(b) {
		return "", off, false
	}
	n := int(b[off])
	off++
	if off+n > len(b) {
		return "", off, false
	}
	return string(b[off : off+n]), off + n, true
}

func (c *ctx) dissectAMQP(b []byte, base int) bool {
	if !looksLikeAMQP(b) {
		return false
	}
	c.addLayer("amqp")
	c.proto = "amqp"
	root := newNode("Advanced Message Queuing Protocol 0-9-1", base, len(b))
	info := "AMQP"
	if bytes.Equal(b[:4], []byte("AMQP")) {
		root.add(c.newField(fmt.Sprintf("Protocol Header: AMQP %d-%d-%d", b[4], b[5], b[6]), "", base, 8))
		c.addRoot(root)
		c.appInfo = "AMQP protocol header"
		return true
	}
	off := 0
	for off+8 <= len(b) && off+8 < len(b) {
		typ := b[off]
		channel := be16(b[off+1 : off+3])
		size := int(be32(b[off+3 : off+7]))
		if size < 0 || off+8+size > len(b) {
			break
		}
		body := b[off+7 : off+7+size]
		n := c.newNode(fmt.Sprintf("AMQP Frame type=%d channel=%d", typ, channel), base+off, 8+size)
		n.add(c.newField(fmt.Sprintf("Frame Type: %d", typ), "", base+off, 1),
			c.newField(fmt.Sprintf("Channel: %d", channel), "", base+off+1, 2),
			c.newField(fmt.Sprintf("Payload Size: %d", size), "", base+off+3, 4))
		switch typ {
		case 1: // method
			if len(body) >= 4 {
				classID, methodID := be16(body[:2]), be16(body[2:4])
				name := amqpMethods[uint32(classID)<<16|uint32(methodID)]
				if name == "" {
					name = fmt.Sprintf("class=%d method=%d", classID, methodID)
				}
				n.add(c.newField("Method: "+name, "", base+off+7, 4))
				pos := 4
				if s, next, ok := amqpShortString(body, pos); ok {
					n.add(c.newField("Argument: "+s, "", base+off+7+pos, next-pos))
					pos = next
				}
				info = "AMQP " + name
			}
		case 2:
			n.add(c.newField("Content Header", "", base+off+7, size))
		case 3:
			n.add(c.newField("Content Body", printablePreview(body, 120), base+off+7, size))
		case 8:
			n.add(c.newField("Heartbeat", "", base+off+7, 0))
		}
		root.add(n)
		off += 8 + size
		if off < len(b) && b[off-1] == 0xce {
			continue
		}
	}
	c.addRoot(root)
	c.appInfo = shorten(info, 160)
	return true
}

func init() {
	RegisterPlugin(pluginSpec{Name: "amqp", Priority: 115, Transport: TransportTCP,
		Match: func(_ *ctx, sport, dport uint16, b []byte) bool {
			return (sport == 5672 || dport == 5672 || sport == 5671 || dport == 5671) && looksLikeAMQP(b)
		}, Dissect: func(c *ctx, b []byte, base int) bool { return c.dissectAMQP(b, base) }, Display: "AMQP"})
}
