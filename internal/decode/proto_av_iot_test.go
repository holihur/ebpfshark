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

func TestAMQPMethod(t *testing.T) {
	body := []byte{0, 10, 0, 10, 4, 't', 'e', 's', 't'}
	b := make([]byte, 7+len(body)+1)
	b[0] = 1
	b[1], b[2] = 0, 1
	binary.BigEndian.PutUint32(b[3:7], uint32(len(body)))
	copy(b[7:], body)
	b[len(b)-1] = 0xce
	c := appCtx(b)
	if !c.dissectAMQP(b, 0) || !strings.Contains(c.appInfo, "connection.start") {
		t.Fatalf("info=%q", c.appInfo)
	}
}

func TestBACnetReadProperty(t *testing.T) {
	b := []byte{0x81, 0x0a, 0x00, 0x0a, 0x01, 0x00, 0x00, 0x05, 0x01, 12}
	c := appCtx(b)
	if !c.dissectBACnet(b, 0) || !strings.Contains(c.appInfo, "ReadProperty") {
		t.Fatalf("info=%q", c.appInfo)
	}
}

func TestOPCUAHello(t *testing.T) {
	b := make([]byte, 28)
	copy(b, "HEL")
	b[3] = 'F'
	binary.LittleEndian.PutUint32(b[4:8], 28)
	binary.LittleEndian.PutUint32(b[8:12], 0)
	binary.LittleEndian.PutUint32(b[12:16], 65536)
	binary.LittleEndian.PutUint32(b[16:20], 65536)
	binary.LittleEndian.PutUint32(b[20:24], 0)
	binary.LittleEndian.PutUint32(b[24:28], 0)
	c := appCtx(b)
	if !c.dissectOPCUA(b, 0) || !strings.Contains(c.appInfo, "OPC UA HEL") {
		t.Fatalf("info=%q", c.appInfo)
	}
}

func TestLoRaWANPush(t *testing.T) {
	b := []byte{2, 0, 1, 0, 1, 2, 3, 4, 5, 6, 7, 8}
	b = append(b, []byte(`{"rxpk":[{"freq":868.1,"datr":"SF7BW125","rssi":-42}]}`)...)
	c := appCtx(b)
	if !c.dissectLoRaWAN(b, 0) || !strings.Contains(c.appInfo, "PUSH_DATA") {
		t.Fatalf("info=%q", c.appInfo)
	}
}

func TestHLSManifest(t *testing.T) {
	b := []byte("HTTP/1.1 200 OK\r\nContent-Type: application/vnd.apple.mpegurl\r\n\r\n#EXTM3U\n#EXT-X-VERSION:3\n#EXTINF:6.0,\nseg1.ts\n")
	c := appCtx(b)
	if !c.dissectHTTP(b, 0) || !c.m.HasLayer("hls") {
		t.Fatalf("layers=%v info=%q", c.m.Layers, c.appInfo)
	}
}

func TestRTPAV1(t *testing.T) {
	b := []byte{0x10, 0x0a}
	c := appCtx(b)
	if !c.dissectAV1(b, 0, newNode("rtp", 0, len(b))) || !c.m.HasLayer("av1") {
		t.Fatalf("layers=%v", c.m.Layers)
	}
}
