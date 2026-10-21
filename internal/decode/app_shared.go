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
