package decode

import "testing"

func TestDASHManifest(t *testing.T) {
	body := `<?xml version="1.0"?><MPD type="static" mediaPresentationDuration="PT10S" minBufferTime="PT2S"><Period><AdaptationSet mimeType="video/mp4"><Representation bandwidth="1000000" width="1280" height="720"/></AdaptationSet></Period></MPD>`
	b := []byte("HTTP/1.1 200 OK\r\nContent-Type: application/dash+xml\r\n\r\n" + body)
	c := appCtx(b)
	if !c.dissectHTTP(b, 0) || !c.m.HasLayer("dash") {
		t.Fatalf("layers=%v info=%q", c.m.Layers, c.appInfo)
	}
}
