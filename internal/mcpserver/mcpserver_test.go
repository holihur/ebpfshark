package mcpserver

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"ebpfshark/internal/capture"
	"ebpfshark/internal/packet"
	"ebpfshark/internal/store"
)

func testServer(t *testing.T) (*mcp.Server, *store.Store) {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	st := store.New(1000)
	mgr := capture.NewManager(st, log)
	p := &packet.Packet{
		Time:     time.Unix(1, 0),
		Summary:  packet.Summary{Protocol: "TCP", Src: "10.0.0.1:1234", Dst: "10.0.0.2:80", Info: "GET /"},
		WireLen:  100,
		CapLen:   100,
		LinkType: packet.LinkEthernet,
		Meta: packet.Meta{
			Layers:     []string{"eth", "ip", "tcp"},
			SrcIP:      netip.MustParseAddr("10.0.0.1"),
			DstIP:      netip.MustParseAddr("10.0.0.2"),
			SrcPort:    1234,
			DstPort:    80,
			TCPSeq:     100,
			TCPFlags:   0x18,
			TCPPayload: []byte("GET / HTTP/1.1\r\n"),
		},
	}
	st.Add(p)
	return New(st, mgr, "test", 9999), st
}

func connect(t *testing.T) (*mcp.ClientSession, func()) {
	t.Helper()
	srv, _ := testServer(t)
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.Run(ctx, serverTransport)
	}()
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	sess, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	return sess, func() {
		sess.Close()
		cancel()
		<-done
	}
}

func call(t *testing.T, sess *mcp.ClientSession, name string, args any) string {
	t.Helper()
	res, err := sess.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Content) == 0 {
		t.Fatalf("%s returned no content", name)
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("%s content type %T", name, res.Content[0])
	}
	return tc.Text
}

func TestTools(t *testing.T) {
	sess, closeFn := connect(t)
	defer closeFn()
	ctx := context.Background()

	tools, err := sess.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools.Tools) < 10 {
		t.Fatalf("only %d tools registered", len(tools.Tools))
	}

	var v map[string]any
	if err := json.Unmarshal([]byte(call(t, sess, "validate_filter", map[string]any{"filter": "tcp port 443"})), &v); err != nil {
		t.Fatal(err)
	}
	if v["valid"] != true {
		t.Fatalf("valid filter rejected: %v", v)
	}
	_ = json.Unmarshal([]byte(call(t, sess, "validate_filter", map[string]any{"filter": "bogus.field == 1"})), &v)
	if v["valid"] != false {
		t.Fatalf("invalid filter accepted: %v", v)
	}

	var pkts struct {
		Count   int `json:"count"`
		Packets []struct {
			ID uint64 `json:"id"`
		} `json:"packets"`
	}
	if err := json.Unmarshal([]byte(call(t, sess, "query_packets", map[string]any{"filter": "tcp", "limit": 10})), &pkts); err != nil {
		t.Fatal(err)
	}
	if pkts.Count != 1 || len(pkts.Packets) != 1 {
		t.Fatalf("query_packets = %+v", pkts)
	}

	var stream struct {
		AtoB struct {
			CapturedBytes int    `json:"capturedBytes"`
			Text          string `json:"text"`
		} `json:"aToB"`
	}
	if err := json.Unmarshal([]byte(call(t, sess, "follow_stream", map[string]any{"packetId": pkts.Packets[0].ID})), &stream); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(stream.AtoB.Text, "GET / HTTP/1.1") {
		t.Fatalf("stream = %+v", stream)
	}

	if out := call(t, sess, "get_status", map[string]any{}); !strings.Contains(out, `"version": "test"`) {
		t.Fatalf("status = %s", out)
	}
}

type headerTransport struct {
	token string
}

func (h headerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set("Authorization", "Bearer "+h.token)
	return http.DefaultTransport.RoundTrip(req)
}

func TestHTTPHandlerAuth(t *testing.T) {
	srv, _ := testServer(t)
	ts := httptest.NewServer(HTTPHandler(srv, "secret-token"))
	defer ts.Close()

	res, err := http.Post(ts.URL, "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no token = %d", res.StatusCode)
	}

	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	sess, err := client.Connect(context.Background(), &mcp.StreamableClientTransport{
		Endpoint:             ts.URL,
		HTTPClient:           &http.Client{Transport: headerTransport{token: "secret-token"}},
		DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	tools, err := sess.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools.Tools) < 10 {
		t.Fatalf("got %d tools", len(tools.Tools))
	}
}
