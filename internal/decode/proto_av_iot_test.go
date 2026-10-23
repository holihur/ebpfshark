//go:build full

package decode

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestCoAPGet(t *testing.T) {
	b := []byte{0x41, 0x01, 0x12, 0x34, 0xaa, 0xb7}
	b = append(b, "sensors"...)
	b = append(b, 0x04)
	b = append(b, "temp"...)
	c := appCtx(b)
	if !c.dissectCoAP(b, 0) || !strings.Contains(c.appInfo, "/sensors/temp") {
		t.Fatalf("info=%q", c.appInfo)
	}
}

func TestModbusReadRequest(t *testing.T) {
	b := []byte{0, 1, 0, 0, 0, 6, 1, 3, 0, 10, 0, 2}
	c := appCtx(b)
	if !c.dissectModbus(b, 0) || !strings.Contains(c.appInfo, "Read Holding Registers") {
		t.Fatalf("info=%q", c.appInfo)
	}
}

func TestMQTTSNPing(t *testing.T) {
	b := []byte{0x02, 0x16}
	c := appCtx(b)
	if !c.dissectMQTTSN(b, 0) || !strings.Contains(c.appInfo, "PINGREQ") {
		t.Fatalf("info=%q", c.appInfo)
	}
}

func TestRTSPDescribe(t *testing.T) {
	body := "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=test\r\nm=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\n"
	b := []byte("DESCRIBE rtsp://example/live RTSP/1.0\r\nCSeq: 2\r\nContent-Type: application/sdp\r\nContent-Length: " + itoa(len(body)) + "\r\n\r\n" + body)
	c := appCtx(b)
	if !c.dissectRTSP(b, 0) || !strings.Contains(c.appInfo, "DESCRIBE") {
		t.Fatalf("info=%q", c.appInfo)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var out [20]byte
	i := len(out)
	for n > 0 {
		i--
		out[i] = byte('0' + n%10)
		n /= 10
	}
	return string(out[i:])
}

func TestMPEGTSPAT(t *testing.T) {
	b := make([]byte, 188)
	b[0], b[1], b[2], b[3] = 0x47, 0x40, 0x00, 0x10
	p := b[4:]
	p[0] = 0
	p[1] = 0x00
	p[2] = 0xb0
	p[3] = 0x0d
	p[4], p[5] = 0, 1
	p[6] = 0xc1
	p[7], p[8] = 0, 0
	p[9], p[10] = 0, 1
	p[11], p[12] = 0xe0, 0x00
	c := appCtx(b)
	if !c.dissectMPEGTS(b, 0) || !strings.Contains(c.appInfo, "PAT") {
		t.Fatalf("info=%q", c.appInfo)
	}
}

func TestRTPH264AndH265(t *testing.T) {
	h264 := []byte{0x80, 0x60, 0, 1, 0, 0, 0, 1, 1, 2, 3, 4, 0x67, 0x64, 0, 0x1f}
	c := appCtx(h264)
	if !c.dissectRTP(h264, 0) || !c.m.HasLayer("h264") {
		t.Fatalf("h264 layers=%v", c.m.Layers)
	}
	h265 := []byte{0x80, 0x60, 0, 1, 0, 0, 0, 1, 1, 2, 3, 4, 0x40, 0x01}
	c = appCtx(h265)
	if !c.dissectRTP(h265, 0) || !c.m.HasLayer("h265") {
		t.Fatalf("h265 layers=%v", c.m.Layers)
	}
}

func TestRTPAAC(t *testing.T) {
	b := make([]byte, 12+2+4)
	binary.BigEndian.PutUint16(b[2:4], 1)
	b[12], b[13] = 0x00, 0x20 // AU size 4, index 0
	c := appCtx(b)
	if !c.dissectAAC(b[12:], 12, newNode("rtp", 0, len(b))) {
		t.Fatal("AAC not recognized")
	}
}
