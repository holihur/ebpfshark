package decode

import (
	"strings"

	"ebpfshark/internal/packet"
)

func appCtx(b []byte) *ctx {
	return &ctx{data: b, m: packet.Meta{}}
}

func fieldLabels(fields []*Field) []string {
	var out []string
	for _, f := range fields {
		out = append(out, f.Label)
		out = append(out, fieldLabels(f.Children)...)
	}
	return out
}

func containsLabel(labels []string, needle string) bool {
	for _, l := range labels {
		if strings.Contains(l, needle) {
			return true
		}
	}
	return false
}
