package decode

import (
	"bytes"
	"encoding/binary"
	"strings"
)

func shorten(s string, n int) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\r", ""))
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func be64(b []byte) uint64 { return binary.BigEndian.Uint64(b) }

func trimNul(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

func bytesHasPrefixFold(b []byte, s string) bool {
	return len(b) >= len(s) && strings.EqualFold(string(b[:len(s)]), s)
}

func printablePreview(b []byte, n int) string {
	if len(b) > n {
		b = b[:n]
	}
	out := make([]rune, 0, len(b))
	for _, r := range string(b) {
		if r == '\r' || r == '\n' || r == '\t' || (r >= 32 && r < 127) {
			out = append(out, r)
		} else {
			out = append(out, '.')
		}
	}
	return string(out)
}
