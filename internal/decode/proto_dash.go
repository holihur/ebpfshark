package decode

import (
	"fmt"
	"regexp"
	"strings"
)

var dashAttrRE = regexp.MustCompile(`([A-Za-z_:][A-Za-z0-9_.:-]*)="([^"]*)"`)

func looksLikeDASH(b []byte) bool {
	s := strings.TrimSpace(strings.TrimPrefix(string(b), "\ufeff"))
	if strings.HasPrefix(s, "<?xml") {
		if i := strings.Index(s, "?>"); i >= 0 {
			s = strings.TrimSpace(s[i+2:])
		}
	}
	return strings.HasPrefix(s, "<MPD")
}

func (c *ctx) dissectDASH(b []byte, base int, root *Field) bool {
	if !looksLikeDASH(b) {
		return false
	}
	c.addLayer("dash")
	c.proto = "dash"
	s := string(b)
	n := c.newField("MPEG-DASH Media Presentation Description", "", base, len(b))
	seen := map[string]bool{}
	for _, m := range dashAttrRE.FindAllStringSubmatch(s, 128) {
		key, val := m[1], m[2]
		switch key {
		case "mediaPresentationDuration", "minBufferTime", "type", "profiles", "availabilityStartTime", "minimumUpdatePeriod", "bandwidth", "width", "height", "codecs", "mimeType", "startNumber":
			if seen[key] {
				continue
			}
			seen[key] = true
			n.add(c.newField(key+": "+val, "", base, 0))
		}
	}
	if i := strings.Index(s, "<BaseURL>"); i >= 0 {
		if j := strings.Index(s[i+9:], "</BaseURL>"); j >= 0 {
			n.add(c.newField("BaseURL: "+strings.TrimSpace(s[i+9:i+9+j]), "", base+i, j))
		}
	}
	root.add(n)
	c.appInfo = fmt.Sprintf("DASH manifest (%d bytes)", len(b))
	return true
}
