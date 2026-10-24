package server

import (
	"bufio"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"ebpfshark/internal/auth"
	"ebpfshark/internal/store"
)

func newTestServer(t *testing.T, enabled bool, password string) *httptest.Server {
	t.Helper()
	web := fstest.MapFS{
		"index.html":    &fstest.MapFile{Data: []byte("<!doctype html><html>test-index</html>")},
		"assets/app.js": &fstest.MapFile{Data: []byte("console.log('test')")},
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	st := store.New(1000)
	svc := auth.New("admin", password, enabled, time.Hour)
	s := New(st, nil, log, web, 0, svc)
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func newClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Jar: jar}
}

func do(t *testing.T, client *http.Client, method, url, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestAuthGate(t *testing.T) {
	ts := newTestServer(t, true, "s3cret-pass")
	client := newClient(t)

	// Static UI and health are public.
	res := do(t, client, http.MethodGet, ts.URL+"/", "")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET / = %d", res.StatusCode)
	}
	res.Body.Close()
	res = do(t, client, http.MethodGet, ts.URL+"/api/health", "")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("health = %d", res.StatusCode)
	}
	res.Body.Close()

	// API data requires a session.
	res = do(t, client, http.MethodGet, ts.URL+"/api/stats", "")
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated stats = %d, want 401", res.StatusCode)
	}
	res.Body.Close()

	res = do(t, client, http.MethodGet, ts.URL+"/api/auth/session", "")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("session = %d", res.StatusCode)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if !strings.Contains(string(body), `"authenticated":false`) {
		t.Fatalf("unexpected session body: %s", body)
	}

	// Wrong password is rejected.
	res = do(t, client, http.MethodPost, ts.URL+"/api/auth/login", `{"username":"admin","password":"wrong"}`)
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad login = %d", res.StatusCode)
	}
	res.Body.Close()

	// Correct password sets a cookie.
	res = do(t, client, http.MethodPost, ts.URL+"/api/auth/login", `{"username":"admin","password":"s3cret-pass"}`)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("login = %d", res.StatusCode)
	}
	res.Body.Close()
	if len(client.Jar.Cookies(mustURL(t, ts.URL))) == 0 {
		t.Fatal("login did not set a session cookie")
	}

	// Authenticated request succeeds.
	res = do(t, client, http.MethodGet, ts.URL+"/api/stats", "")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("authenticated stats = %d", res.StatusCode)
	}
	res.Body.Close()

	// Logout invalidates the session.
	res = do(t, client, http.MethodPost, ts.URL+"/api/auth/logout", "")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("logout = %d", res.StatusCode)
	}
	res.Body.Close()
	res = do(t, client, http.MethodGet, ts.URL+"/api/stats", "")
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("stats after logout = %d, want 401", res.StatusCode)
	}
	res.Body.Close()
}

func TestAuthDisabled(t *testing.T) {
	ts := newTestServer(t, false, "")
	client := newClient(t)
	res := do(t, client, http.MethodGet, ts.URL+"/api/stats", "")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("stats with auth disabled = %d", res.StatusCode)
	}
	res.Body.Close()
	res = do(t, client, http.MethodGet, ts.URL+"/api/auth/session", "")
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if !strings.Contains(string(body), `"authenticated":true`) {
		t.Fatalf("unexpected session body: %s", body)
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestLocalIPCEndpoints(t *testing.T) {
	ts := newTestServer(t, false, "")
	client := newClient(t)

	for _, path := range []string{"/api/ipc", "/api/ipc/sockets", "/api/ipc/events?limit=10", "/api/ipc/streams?limit=10"} {
		res := do(t, client, http.MethodGet, ts.URL+path, "")
		if res.StatusCode != http.StatusOK {
			t.Fatalf("GET %s = %d", path, res.StatusCode)
		}
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if !strings.Contains(string(body), `"status"`) && path != "/api/ipc" {
			t.Fatalf("GET %s missing status: %s", path, body)
		}
	}

	res := do(t, client, http.MethodPost, ts.URL+"/api/ipc/clear", "")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/ipc/clear = %d", res.StatusCode)
	}
	res.Body.Close()
	res = do(t, client, http.MethodPost, ts.URL+"/api/ipc/stop", "")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/ipc/stop = %d", res.StatusCode)
	}
	res.Body.Close()
}

func TestLocalIPCStreamAndExport(t *testing.T) {
	ts := newTestServer(t, false, "")
	client := newClient(t)

	res := do(t, client, http.MethodGet, ts.URL+"/api/ipc/stream?after=0", "")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/ipc/stream = %d", res.StatusCode)
	}
	if ct := res.Header.Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
		t.Fatalf("SSE content type = %q", ct)
	}
	reader := bufio.NewReader(res.Body)
	foundReady := false
	for i := 0; i < 10; i++ {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		if strings.HasPrefix(line, "event: ready") {
			foundReady = true
			break
		}
	}
	res.Body.Close()
	if !foundReady {
		t.Fatal("SSE did not emit a ready event")
	}

	res = do(t, client, http.MethodGet, ts.URL+"/api/ipc/export?format=jsonl", "")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/ipc/export = %d", res.StatusCode)
	}
	if ct := res.Header.Get("Content-Type"); !strings.Contains(ct, "ndjson") {
		t.Fatalf("export content type = %q", ct)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if len(body) != 0 {
		t.Fatalf("empty store export = %q", body)
	}
}
