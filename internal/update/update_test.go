package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestIsNewer(t *testing.T) {
	cases := []struct {
		latest, current string
		want            bool
		wantErr         bool
	}{
		{"0.2.0", "0.1.0", true, false},
		{"v0.1.0", "0.1.0", false, false},
		{"0.1.0", "0.1.0-dev", true, false},
		{"0.1.0", "0.2.0", false, false},
		{"bad-version", "0.1.0", false, true},
	}
	for _, tc := range cases {
		got, err := isNewer(tc.latest, tc.current)
		if (err != nil) != tc.wantErr || got != tc.want {
			t.Errorf("isNewer(%q,%q) = %v,%v want %v,err=%v", tc.latest, tc.current, got, err, tc.want, tc.wantErr)
		}
	}
}

func TestValidateURL(t *testing.T) {
	for _, ok := range []string{"https://example.com/a", "http://127.0.0.1:8080/a", "http://localhost/a"} {
		if _, err := validateURL(ok); err != nil {
			t.Errorf("validateURL(%q): %v", ok, err)
		}
	}
	for _, bad := range []string{"http://example.com/a", "ftp://example.com/a", "not a url", ""} {
		if _, err := validateURL(bad); err == nil {
			t.Errorf("validateURL(%q) should fail", bad)
		}
	}
}

func testServer(t *testing.T, binary []byte, version string, corrupt bool) (*httptest.Server, *int32) {
	t.Helper()
	sum := sha256.Sum256(binary)
	hash := hex.EncodeToString(sum[:])
	if corrupt {
		other := sha256.Sum256([]byte("other"))
		hash = hex.EncodeToString(other[:])
	}
	var hits int32
	var base string
	mux := http.NewServeMux()
	mux.HandleFunc("/manifest.json", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(Manifest{
			Version: version,
			URL:     base + "/bin",
			SHA256:  hash,
		})
	})
	mux.HandleFunc("/bin", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = w.Write(binary)
	})
	ts := httptest.NewServer(mux)
	base = ts.URL
	t.Cleanup(ts.Close)
	return ts, &hits
}

func testExe(t *testing.T, content []byte) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "ebpfshark")
	if err := os.WriteFile(path, content, 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func newTestUpdater(t *testing.T, exe, manifest string, client *http.Client, restart func()) *Updater {
	t.Helper()
	return New(Config{
		Enabled:        true,
		Interval:       time.Minute,
		ManifestURL:    manifest,
		CurrentVersion: "0.1.0",
		ExePath:        exe,
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		HTTPClient:     client,
		Restart:        restart,
	})
}

var newELF = append([]byte("\x7fELF"), []byte("new-binary-content")...)

func TestCheckAndReplace(t *testing.T) {
	ts, hits := testServer(t, newELF, "9.9.9", false)
	exe := testExe(t, []byte("\x7fELF-old"))
	restarted := make(chan struct{}, 1)
	u := newTestUpdater(t, exe, ts.URL+"/manifest.json", ts.Client(), func() { restarted <- struct{}{} })

	if err := u.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(newELF) {
		t.Fatalf("binary not replaced: %q", got)
	}
	info, _ := os.Stat(exe)
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("mode = %o", info.Mode().Perm())
	}
	if atomic.LoadInt32(hits) != 1 {
		t.Fatalf("download hits = %d", *hits)
	}
	st := u.Status()
	if !strings.Contains(st.LastResult, "updated") || st.LatestVersion != "9.9.9" || st.UpdateAvailable {
		t.Fatalf("status = %+v", st)
	}
	select {
	case <-restarted:
	case <-time.After(4 * time.Second):
		t.Fatal("restart callback was not called")
	}
}

func TestCheckBadChecksum(t *testing.T) {
	ts, _ := testServer(t, newELF, "9.9.9", true)
	exe := testExe(t, []byte("\x7fELF-old"))
	u := newTestUpdater(t, exe, ts.URL+"/manifest.json", ts.Client(), nil)
	if err := u.Check(context.Background()); err == nil {
		t.Fatal("expected checksum error")
	}
	got, _ := os.ReadFile(exe)
	if string(got) != "\x7fELF-old" {
		t.Fatal("binary was replaced despite bad checksum")
	}
	if u.Status().LastError == "" {
		t.Fatal("status should contain an error")
	}
}

func TestCheckUpToDate(t *testing.T) {
	ts, hits := testServer(t, newELF, "0.1.0", false)
	exe := testExe(t, []byte("\x7fELF-old"))
	u := newTestUpdater(t, exe, ts.URL+"/manifest.json", ts.Client(), nil)
	if err := u.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt32(hits) != 0 {
		t.Fatal("binary should not be downloaded")
	}
	if u.Status().LastResult != "up to date" {
		t.Fatalf("status = %+v", u.Status())
	}
}

func TestCheckSkippedWhileCapturing(t *testing.T) {
	ts, hits := testServer(t, newELF, "9.9.9", false)
	exe := testExe(t, []byte("\x7fELF-old"))
	u := newTestUpdater(t, exe, ts.URL+"/manifest.json", ts.Client(), nil)
	u.cfg.CanUpdate = func() bool { return false }
	if err := u.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt32(hits) != 0 {
		t.Fatal("download should be skipped")
	}
	if !strings.Contains(u.Status().LastResult, "skipped") {
		t.Fatalf("status = %+v", u.Status())
	}
}

func TestInsecureManifestURL(t *testing.T) {
	exe := testExe(t, []byte("\x7fELF-old"))
	u := newTestUpdater(t, exe, "http://example.com/manifest.json", http.DefaultClient, nil)
	if err := u.Check(context.Background()); err == nil {
		t.Fatal("expected insecure URL error")
	}
}

func TestDisabled(t *testing.T) {
	u := New(Config{Enabled: false, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err := u.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if u.Status().Enabled {
		t.Fatal("status should be disabled")
	}
}
