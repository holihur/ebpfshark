//go:build full

package decode

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestMySQLOK(t *testing.T) {
	b := []byte{3, 0, 0, 1, 0x00, 0x00, 0x00}
	c := appCtx(b)
	if !c.dissectMySQL(b, 0) || !strings.Contains(c.appInfo, "OK") {
		t.Fatalf("info=%q", c.appInfo)
	}
}

func TestRADIUSAccessRequest(t *testing.T) {
	b := make([]byte, 20)
	b[0], b[1] = 1, 7
	binary.BigEndian.PutUint16(b[2:4], 26)
	b = append(b, 1, 6, 'a', 'l', 'i', 'c', 'e')
	c := appCtx(b)
	if !c.dissectRADIUS(b, 0) || !strings.Contains(c.appInfo, "Access-Request") {
		t.Fatalf("info=%q", c.appInfo)
	}
}

func TestRTPPacket(t *testing.T) {
	b := []byte{0x80, 0x60, 0, 1, 0, 0, 0, 1, 1, 2, 3, 4}
	c := appCtx(b)
	if !c.dissectRTP(b, 0) || !strings.Contains(c.appInfo, "RTP PT=96") {
		t.Fatalf("info=%q", c.appInfo)
	}
}

func TestWebSocketText(t *testing.T) {
	b := []byte{0x81, 0x05, 'h', 'e', 'l', 'l', 'o'}
	c := appCtx(b)
	if !c.dissectWebSocket(b, 0) || !strings.Contains(c.appInfo, "Text") {
		t.Fatalf("info=%q", c.appInfo)
	}
}

func TestNetFlowV5(t *testing.T) {
	b := make([]byte, 24)
	binary.BigEndian.PutUint16(b[0:2], 5)
	binary.BigEndian.PutUint16(b[2:4], 0)
	c := appCtx(b)
	if !c.dissectNetFlow(b, 0) || !strings.Contains(c.appInfo, "NetFlow v5") {
		t.Fatalf("info=%q", c.appInfo)
	}
}
