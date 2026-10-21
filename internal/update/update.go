// Package update implements optional self-update from a signed-by-checksum
// release manifest.
package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/mod/semver"
)

// MaxBinarySize bounds a downloaded update.
const MaxBinarySize int64 = 256 << 20

// Manifest is the JSON document served by the update server.
type Manifest struct {
	Version string `json:"version"`
	URL     string `json:"url"`
	SHA256  string `json:"sha256"`
	Notes   string `json:"notes,omitempty"`
}

// Status is exposed through the API and logs.
type Status struct {
	Enabled         bool   `json:"enabled"`
	ManifestURL     string `json:"manifestUrl,omitempty"`
	CurrentVersion  string `json:"currentVersion"`
	IntervalSeconds int64  `json:"intervalSeconds"`
	LastCheck       string `json:"lastCheck,omitempty"`
	LastResult      string `json:"lastResult,omitempty"`
	LastError       string `json:"lastError,omitempty"`
	LatestVersion   string `json:"latestVersion,omitempty"`
	UpdateAvailable bool   `json:"updateAvailable"`
}

// Config configures an Updater.
type Config struct {
	Enabled        bool
	Interval       time.Duration
	ManifestURL    string
	CurrentVersion string
	// ExePath overrides the binary that gets replaced (tests).
	ExePath    string
	Logger     *slog.Logger
	HTTPClient *http.Client
	// CanUpdate is checked before downloading; return false to defer.
	CanUpdate func() bool
	// Restart is called after a successful replacement. It should re-exec or
	// exit so the supervisor starts the new binary.
	Restart func()
}

// Updater periodically checks the manifest and replaces the binary.
type Updater struct {
	cfg    Config
	logger *slog.Logger
	client *http.Client

	mu     sync.Mutex
	status Status
}

// New creates an updater.
func New(cfg Config) *Updater {
	if cfg.Interval <= 0 {
		cfg.Interval = 10 * time.Minute
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{}
	}
	return &Updater{
		cfg:    cfg,
		logger: cfg.Logger,
		client: cfg.HTTPClient,
		status: Status{
			Enabled:         cfg.Enabled,
			ManifestURL:     cfg.ManifestURL,
			CurrentVersion:  cfg.CurrentVersion,
			IntervalSeconds: int64(cfg.Interval.Seconds()),
		},
	}
}

// Start launches the periodic check loop. It returns immediately.
func (u *Updater) Start(ctx context.Context) {
	if !u.cfg.Enabled {
		u.logger.Info("auto-update disabled")
		return
	}
	if strings.TrimSpace(u.cfg.ManifestURL) == "" {
		u.logger.Warn("auto-update enabled but no update URL configured; set -update-url / EBPFSHARK_UPDATE_URL or use -auto-update=false")
		return
	}
	u.logger.Info("auto-update enabled", "interval", u.cfg.Interval.String(), "manifest", u.cfg.ManifestURL)

	go func() {
		// Give the service time to settle before the first check.
		initial := time.NewTimer(30 * time.Second)
		defer initial.Stop()
		select {
		case <-ctx.Done():
			return
		case <-initial.C:
		}
		for {
			if err := u.Check(ctx); err != nil {
				u.logger.Warn("auto-update check failed", "err", err)
			}
			timer := time.NewTimer(u.cfg.Interval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}()
}

// Check performs one update check. It is safe to call manually.
func (u *Updater) Check(ctx context.Context) error {
	if !u.cfg.Enabled {
		return nil
	}
	if strings.TrimSpace(u.cfg.ManifestURL) == "" {
		return fmt.Errorf("update URL is empty")
	}
	u.setStatus(func(s *Status) {
		s.LastCheck = time.Now().UTC().Format(time.RFC3339)
		s.LastError = ""
	})
	if u.cfg.CanUpdate != nil && !u.cfg.CanUpdate() {
		u.setStatus(func(s *Status) { s.LastResult = "skipped: capture is running" })
		u.logger.Info("auto-update skipped while capture is running")
		return nil
	}

	manifestURL, err := validateURL(u.cfg.ManifestURL)
	if err != nil {
		return u.fail(err)
	}
	manifest, err := u.fetchManifest(ctx, manifestURL)
	if err != nil {
		return u.fail(err)
	}
	newer, err := isNewer(manifest.Version, u.cfg.CurrentVersion)
	if err != nil {
		return u.fail(err)
	}
	u.setStatus(func(s *Status) {
		s.LatestVersion = manifest.Version
		s.UpdateAvailable = newer
	})
	if !newer {
		u.setStatus(func(s *Status) { s.LastResult = "up to date" })
		u.logger.Debug("auto-update: up to date", "version", u.cfg.CurrentVersion)
		return nil
	}

	u.logger.Info("auto-update: new version found", "current", u.cfg.CurrentVersion, "latest", manifest.Version)
	downloadURL, err := resolveURL(manifestURL, manifest.URL)
	if err != nil {
		return u.fail(err)
	}
	if _, err := validateURL(downloadURL.String()); err != nil {
		return u.fail(err)
	}
	if len(manifest.SHA256) != sha256.Size*2 {
		return u.fail(fmt.Errorf("manifest sha256 must be %d hex characters", sha256.Size*2))
	}
	expected, err := hex.DecodeString(manifest.SHA256)
	if err != nil {
		return u.fail(fmt.Errorf("invalid manifest sha256: %w", err))
	}

	exe, err := u.executable()
	if err != nil {
		return u.fail(err)
	}
	if err := u.downloadAndReplace(ctx, downloadURL.String(), exe, expected); err != nil {
		return u.fail(err)
	}

	u.setStatus(func(s *Status) {
		s.LastResult = fmt.Sprintf("updated to %s", manifest.Version)
		s.LastError = ""
		s.UpdateAvailable = false
		s.LatestVersion = manifest.Version
	})
	u.logger.Info("auto-update: binary replaced", "version", manifest.Version, "path", exe)
	if u.cfg.Restart != nil {
		go func() {
			time.Sleep(1500 * time.Millisecond)
			u.cfg.Restart()
		}()
	} else {
		u.logger.Warn("auto-update: restart is required to use the new binary")
	}
	return nil
}

// Status returns a copy of the current updater status.
func (u *Updater) Status() Status {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.status
}

func (u *Updater) fail(err error) error {
	u.setStatus(func(s *Status) {
		s.LastError = err.Error()
		s.LastResult = "failed"
	})
	return err
}

func (u *Updater) setStatus(fn func(*Status)) {
	u.mu.Lock()
	fn(&u.status)
	u.mu.Unlock()
}

func (u *Updater) executable() (string, error) {
	exe := u.cfg.ExePath
	if exe == "" {
		var err error
		exe, err = os.Executable()
		if err != nil {
			return "", fmt.Errorf("locate executable: %w", err)
		}
	}
	exe, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return "", fmt.Errorf("resolve executable: %w", err)
	}
	return exe, nil
}

func (u *Updater) fetchManifest(ctx context.Context, manifestURL *url.URL) (*Manifest, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, manifestURL.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "ebpfshark/"+u.cfg.CurrentVersion)
	res, err := u.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch update manifest: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("update manifest returned HTTP %d", res.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read update manifest: %w", err)
	}
	var manifest Manifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		return nil, fmt.Errorf("parse update manifest: %w", err)
	}
	if manifest.Version == "" || manifest.URL == "" || manifest.SHA256 == "" {
		return nil, fmt.Errorf("update manifest requires version, url and sha256")
	}
	return &manifest, nil
}

func (u *Updater) downloadAndReplace(ctx context.Context, downloadURL, exe string, expected []byte) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "ebpfshark/"+u.cfg.CurrentVersion)
	res, err := u.client.Do(req)
	if err != nil {
		return fmt.Errorf("download update: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("update download returned HTTP %d", res.StatusCode)
	}

	dir := filepath.Dir(exe)
	tmp, err := os.CreateTemp(dir, ".ebpfshark-update-*")
	if err != nil {
		return fmt.Errorf("create update file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	hasher := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, hasher), io.LimitReader(res.Body, MaxBinarySize+1))
	if err != nil {
		tmp.Close()
		return fmt.Errorf("write update: %w", err)
	}
	if n > MaxBinarySize {
		tmp.Close()
		return fmt.Errorf("update exceeds %d bytes", MaxBinarySize)
	}
	if !equalBytes(hasher.Sum(nil), expected) {
		tmp.Close()
		return fmt.Errorf("update checksum mismatch")
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync update: %w", err)
	}
	if err := tmp.Chmod(0o755); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod update: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close update: %w", err)
	}

	if err := checkELF(tmpName); err != nil {
		return err
	}
	if err := os.Rename(tmpName, exe); err != nil {
		return fmt.Errorf("replace %s: %w", exe, err)
	}
	return nil
}

func checkELF(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var magic [4]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil {
		return fmt.Errorf("read update binary: %w", err)
	}
	if string(magic[:]) != "\x7fELF" {
		return fmt.Errorf("update is not a Linux ELF binary")
	}
	return nil
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

func validateURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("invalid update URL %q", raw)
	}
	switch u.Scheme {
	case "https":
		return u, nil
	case "http":
		host := u.Hostname()
		if host == "127.0.0.1" || host == "localhost" || host == "::1" {
			return u, nil
		}
		return nil, fmt.Errorf("refusing insecure update URL %q (use HTTPS)", raw)
	default:
		return nil, fmt.Errorf("unsupported update URL scheme %q", u.Scheme)
	}
}

func resolveURL(base *url.URL, ref string) (*url.URL, error) {
	r, err := url.Parse(ref)
	if err != nil {
		return nil, fmt.Errorf("invalid download URL %q: %w", ref, err)
	}
	return base.ResolveReference(r), nil
}

func isNewer(latest, current string) (bool, error) {
	l := normalizeVersion(latest)
	c := normalizeVersion(current)
	if !semver.IsValid(l) {
		return false, fmt.Errorf("invalid version %q in update manifest", latest)
	}
	if !semver.IsValid(c) {
		// Development builds or non-semver versions: update if different.
		return l != c, nil
	}
	return semver.Compare(l, c) > 0, nil
}

func normalizeVersion(v string) string {
	v = strings.TrimSpace(v)
	if v != "" && !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	return v
}
