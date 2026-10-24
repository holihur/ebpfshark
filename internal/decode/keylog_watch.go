package decode

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

var keylogAuto atomic.Bool

func init() { keylogAuto.Store(true) }

// SetKeyLogAuto controls automatic discovery of keylog files from running
// processes. Explicit -tls-keylog paths are still watched when this is off.
func SetKeyLogAuto(enabled bool) { keylogAuto.Store(enabled) }

// KeyLogAutoEnabled reports whether automatic discovery is enabled.
func KeyLogAutoEnabled() bool { return keylogAuto.Load() }

// WatchKeyLogs discovers SSLKEYLOGFILE paths from running processes (both the
// environment and the common --tls-keylog argument) and reloads files when
// they change. It cannot create keys: the client must be started with keylog
// output enabled.
func WatchKeyLogs(ctx context.Context, explicit string, interval time.Duration) {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	seen := make(map[string]int64)
	load := func(path string) {
		st, err := os.Stat(path)
		if err != nil || st.IsDir() {
			return
		}
		key := st.ModTime().UnixNano() ^ st.Size()
		if seen[path] == key {
			return
		}
		n, err := loadKeyLogFile(path)
		if err != nil {
			return
		}
		seen[path] = key
		if n > 0 {
			slog.Info("TLS keylog auto-loaded", "path", path, "newLines", n, "entries", KeyLogEntries())
		}
	}
	scan := func() {
		paths := make([]string, 0, 8)
		if explicit != "" {
			paths = append(paths, explicit)
		}
		if KeyLogAutoEnabled() {
			paths = append(paths, DiscoverKeyLogPaths()...)
		}
		dedup := make(map[string]struct{}, len(paths))
		for _, p := range paths {
			p = filepath.Clean(strings.TrimSpace(p))
			if p == "" {
				continue
			}
			if _, ok := dedup[p]; ok {
				continue
			}
			dedup[p] = struct{}{}
			load(p)
		}
	}
	scan()
	timer := time.NewTicker(interval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			scan()
		}
	}
}

func loadKeyLogFile(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return LoadKeyLogData(data)
}

// DiscoverKeyLogPaths scans /proc for SSLKEYLOGFILE environment variables and
// --tls-keylog command-line arguments. It never reads the key file contents
// itself.
func DiscoverKeyLogPaths() []string {
	paths := make([]string, 0, 4)
	if p := strings.TrimSpace(os.Getenv("SSLKEYLOGFILE")); p != "" {
		paths = append(paths, p)
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return paths
	}
	for _, entry := range entries {
		if !entry.IsDir() || entry.Name()[0] < '0' || entry.Name()[0] > '9' {
			continue
		}
		dir := filepath.Join("/proc", entry.Name())
		if data, err := os.ReadFile(filepath.Join(dir, "environ")); err == nil {
			for _, field := range strings.Split(string(data), "\x00") {
				if strings.HasPrefix(field, "SSLKEYLOGFILE=") {
					paths = append(paths, strings.TrimPrefix(field, "SSLKEYLOGFILE="))
				}
			}
		}
		if data, err := os.ReadFile(filepath.Join(dir, "cmdline")); err == nil {
			args := strings.Split(string(data), "\x00")
			for i := 0; i < len(args); i++ {
				arg := args[i]
				switch {
				case arg == "--tls-keylog" && i+1 < len(args):
					paths = append(paths, args[i+1])
				case strings.HasPrefix(arg, "--tls-keylog="):
					paths = append(paths, strings.TrimPrefix(arg, "--tls-keylog="))
				}
			}
		}
	}
	return paths
}
