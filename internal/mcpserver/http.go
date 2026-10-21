package mcpserver

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// HTTPHandler serves the MCP streamable HTTP transport, protected by a bearer
// token. Stateless mode keeps the handler independent of long-lived sessions.
func HTTPHandler(srv *mcp.Server, token string) http.Handler {
	inner := mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return srv },
		&mcp.StreamableHTTPOptions{Stateless: true},
	)
	expected := sha256.Sum256([]byte(token))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(header, prefix) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="ebpfshark"`)
			http.Error(w, "missing MCP bearer token", http.StatusUnauthorized)
			return
		}
		got := sha256.Sum256([]byte(strings.TrimPrefix(header, prefix)))
		if subtle.ConstantTimeCompare(got[:], expected[:]) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="ebpfshark"`)
			http.Error(w, "invalid MCP bearer token", http.StatusUnauthorized)
			return
		}
		inner.ServeHTTP(w, r)
	})
}
