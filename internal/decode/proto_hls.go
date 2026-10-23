package decode

import (
	"fmt"
	"strconv"
	"strings"
)

func looksLikeHLS(b []byte) bool {
	return strings.HasPrefix(strings.TrimSpace(string(b)), "#EXTM3U")
}

// dissectHLS adds manifest metadata to the enclosing HTTP field tree. It is
// intentionally a manifest parser, not a media segment decoder.
func (c *ctx) dissectHLS(b []byte, base int, root *Field) bool {
	if !looksLikeHLS(b) {
		return false
	}
	c.addLayer("hls")
	c.proto = "hls"
	n := c.newField("HTTP Live Streaming Manifest", "", base, len(b))
	info := "HLS manifest"
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#EXT-X-VERSION:") {
			n.add(c.newField("Version: "+strings.TrimPrefix(line, "#EXT-X-VERSION:"), "", base, 0))
		} else if strings.HasPrefix(line, "#EXT-X-TARGETDURATION:") {
			n.add(c.newField("Target Duration: "+strings.TrimPrefix(line, "#EXT-X-TARGETDURATION:"), "", base, 0))
		} else if strings.HasPrefix(line, "#EXT-X-MEDIA-SEQUENCE:") {
			n.add(c.newField("Media Sequence: "+strings.TrimPrefix(line, "#EXT-X-MEDIA-SEQUENCE:"), "", base, 0))
		} else if strings.HasPrefix(line, "#EXTINF:") {
			v := strings.TrimSuffix(strings.TrimPrefix(line, "#EXTINF:"), ",")
			d, _ := strconv.ParseFloat(v, 64)
			n.add(c.newField(fmt.Sprintf("Segment Duration: %.3fs", d), "", base, 0))
		} else if strings.HasPrefix(line, "#EXT-X-STREAM-INF:") {
			n.add(c.newField("Variant: "+strings.TrimPrefix(line, "#EXT-X-STREAM-INF:"), "", base, 0))
			info = "HLS variant playlist"
		} else if !strings.HasPrefix(line, "#") {
			n.add(c.newField("Segment: "+line, "", base, 0))
		}
	}
	root.add(n)
	c.appInfo = info
	return true
}
