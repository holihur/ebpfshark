package decode

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"io"
	"strings"

	"github.com/andybalholm/brotli"
)

const maxDecodedBody = 8 << 20

// decodeAIBody decodes the HTTP content codings commonly used by AI APIs.
// gzip, deflate, zlib and brotli are supported.
func decodeAIBody(body []byte, encoding string) ([]byte, bool) {
	enc := strings.ToLower(strings.TrimSpace(encoding))
	if enc == "" || enc == "identity" {
		return body, true
	}
	var r io.ReadCloser
	var err error
	switch enc {
	case "gzip", "x-gzip":
		r, err = gzip.NewReader(bytes.NewReader(body))
	case "deflate":
		r = flate.NewReader(bytes.NewReader(body))
	case "zlib":
		r, err = zlib.NewReader(bytes.NewReader(body))
	case "br":
		r = io.NopCloser(brotli.NewReader(bytes.NewReader(body)))
	default:
		return nil, false
	}
	if err != nil {
		return nil, false
	}
	defer r.Close()
	out, err := io.ReadAll(io.LimitReader(r, maxDecodedBody+1))
	if err != nil || len(out) > maxDecodedBody {
		return nil, false
	}
	return out, true
}
