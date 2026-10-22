//go:build full

package decode

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"testing"

	"golang.org/x/net/http2/hpack"
)

func TestHTTP2HPACKHeaders(t *testing.T) {
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	for _, hf := range []hpack.HeaderField{
		{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "https"},
		{Name: ":path", Value: "/index.html"}, {Name: ":authority", Value: "example.com"},
		{Name: "user-agent", Value: "ebpfshark-test"},
	} {
		if err := enc.WriteField(hf); err != nil {
			t.Fatal(err)
		}
	}
	block := buf.Bytes()
	frame := make([]byte, 9+len(block))
	frame[0], frame[1], frame[2] = byte(len(block)>>16), byte(len(block)>>8), byte(len(block))
	frame[3], frame[4] = 1, 0x04
	binary.BigEndian.PutUint32(frame[5:9], 1)
	copy(frame[9:], block)
	c := appCtx(frame)
	c.m.SrcPort, c.m.DstPort = 50000, 8080
	if !c.dissectHTTP2(frame, 0) {
		t.Fatal("HTTP/2 frame not recognized")
	}
	labels := fieldLabels(c.roots)
	for _, want := range []string{":method: GET", ":path: /index.html", ":authority: example.com"} {
		if !containsLabel(labels, want) {
			t.Fatalf("missing %q in %v", want, labels)
		}
	}
}

func TestQUICInitialDecrypt(t *testing.T) {
	dcid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	hello := buildClientHello("quic.example.com")[5:]
	frame := []byte{6, 0}
	if len(hello) < 64 {
		frame = append(frame, byte(len(hello)))
	} else {
		frame = append(frame, 0x40|byte(len(hello)>>8), byte(len(hello)))
	}
	frame = append(frame, hello...)
	frame = append(frame, make([]byte, 64)...) // padding so header protection sample exists
	clientSecret, _, _ := quicInitialSecrets(dcid, 1)
	key, iv, hp, _ := quicPacketKeys(clientSecret)
	pn := uint64(0)
	header := []byte{0xc0, 0, 0, 0, 1, byte(len(dcid))}
	header = append(header, dcid...)
	header = append(header, 0, 0) // SCID len, token len
	length := 1 + len(frame) + 16
	if length < 64 {
		header = append(header, byte(length))
	} else {
		header = append(header, 0x40|byte(length>>8), byte(length))
	}
	pnOffset := len(header)
	header = append(header, byte(pn))
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	ct := aead.Seal(nil, quicNonce(iv, pn), frame, header)
	if _, ok := quicOpen(clientSecret, header, ct, pn); !ok {
		t.Fatal("test packet does not decrypt before header protection")
	}
	packet := append(append([]byte(nil), header...), ct...)
	// Apply header protection.
	hpBlock, _ := aes.NewCipher(hp)
	mask := make([]byte, 16)
	hpBlock.Encrypt(mask, packet[pnOffset+4:pnOffset+20])
	packet[0] ^= mask[0] & 0x0f
	packet[pnOffset] ^= mask[1]

	c := appCtx(packet)
	c.m.SrcPort, c.m.DstPort = 50000, 443
	if !c.dissectQUIC(packet, 0) {
		t.Fatal("QUIC not recognized")
	}
	labels := fieldLabels(c.roots)
	if !containsLabel(labels, "Decrypted QUIC Payload") {
		t.Fatalf("Initial not decrypted: %v", labels)
	}
	if !containsLabel(labels, "Server Name: quic.example.com") {
		t.Fatalf("QUIC SNI missing: %v", labels)
	}
	_ = packet
}

func TestQPACKStaticFields(t *testing.T) {
	block := []byte{0, 0, 0xd1, 0xc1, 0xd7} // :method GET, :path /, :scheme https
	fields, err := decodeQPACK(block)
	if err != nil {
		t.Fatal(err)
	}
	if len(fields) != 3 || fields[0].Name != ":method" || fields[0].Value != "GET" {
		t.Fatalf("fields=%+v", fields)
	}
}

func TestHTTP3Stream(t *testing.T) {
	block := []byte{0, 0, 0xd1, 0xc1, 0xd7}
	frame := []byte{1, byte(len(block))}
	frame = append(frame, block...)
	c := appCtx(nil)
	root := c.newNode("STREAM", 0, 0)
	if !c.parseHTTP3StreamCompat(frame, 0, root) {
		t.Fatal("HTTP/3 stream not parsed")
	}
	labels := fieldLabels(root.Children)
	if !containsLabel(labels, ":method: GET") || !containsLabel(labels, ":path: /") {
		t.Fatalf("missing headers: %v", labels)
	}
}

func TestQPACKDynamicTable(t *testing.T) {
	c := appCtx(nil)
	q := qpackFor(c)
	q.capacity = 4096
	q.feedEncoder([]byte{0x46, 'x', '-', 't', 'e', 's', 't', 0x01, 'v'})
	fields, err := q.decodeFieldSection([]byte{2, 0, 0x80})
	if err != nil {
		t.Fatal(err)
	}
	if len(fields) != 1 || fields[0].Name != "x-test" || fields[0].Value != "v" {
		t.Fatalf("fields=%+v", fields)
	}
}
