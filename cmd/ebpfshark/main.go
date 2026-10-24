package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"ebpfshark/internal/auth"
	"ebpfshark/internal/capture"
	"ebpfshark/internal/decode"
	"ebpfshark/internal/filter"
	"ebpfshark/internal/mcpserver"
	"ebpfshark/internal/mitm"
	"ebpfshark/internal/probe"
	"ebpfshark/internal/server"
	"ebpfshark/internal/store"
	"ebpfshark/internal/update"
)

func defaultMITMCADir() string {
	if dir, err := os.UserConfigDir(); err == nil && dir != "" {
		return filepath.Join(dir, "ebpfshark", "mitm")
	}
	return "/var/lib/ebpfshark/mitm"
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "mcp" {
		runMCPStdio(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "trace" {
		runTrace(os.Args[2:])
		return
	}

	addr := flag.String("addr", env("EBPFSHARK_ADDR", ":9999"), "HTTP listen address")
	maxPackets := flag.Int("max-packets", envInt("EBPFSHARK_MAX_PACKETS", 100000), "packets kept in the ring buffer")
	webDir := flag.String("web-dir", env("EBPFSHARK_WEB_DIR", ""), "serve the UI from this directory instead of the embedded build")
	iface := flag.String("capture", env("EBPFSHARK_IFACE", ""), "comma separated interfaces to capture on at startup")
	snaplen := flag.Uint("snaplen", 2048, "bytes captured per packet (max 2048)")
	sampleRate := flag.Uint("sample-rate", 1, "capture 1 out of every N packets")
	ringSize := flag.Uint("ring-size", 32<<20, "BPF ring buffer size in bytes")
	streamBudget := flag.Int("stream-budget", envInt("EBPFSHARK_STREAM_BUDGET", 64), "TCP reassembly memory budget in MiB")
	autoUpdate := flag.Bool("auto-update", envBool("EBPFSHARK_AUTO_UPDATE", true), "check for binary updates")
	updateInterval := flag.Duration("update-interval", envDuration("EBPFSHARK_UPDATE_INTERVAL", 10*time.Minute), "auto-update check interval")
	updateURL := flag.String("update-url", env("EBPFSHARK_UPDATE_URL", ""), "auto-update manifest URL")
	logLevel := flag.String("log-level", env("EBPFSHARK_LOG_LEVEL", "info"), "debug, info, warn or error")
	excludeSelf := flag.Bool("exclude-self", true, "exclude the HTTP API port from captures")
	authUser := flag.String("auth-user", env("EBPFSHARK_AUTH_USER", "admin"), "login username")
	authPass := flag.String("auth-pass", env("EBPFSHARK_AUTH_PASS", ""), "login password (empty = generate a random one at startup)")
	authTTL := flag.Duration("auth-ttl", 12*time.Hour, "login session lifetime")
	secureCookie := flag.Bool("secure-cookie", false, "set Secure on the session cookie (use behind HTTPS)")
	noAuth := flag.Bool("no-auth", false, "disable authentication (NOT recommended)")
	mcpToken := flag.String("mcp-token", env("EBPFSHARK_MCP_TOKEN", ""), "bearer token for the HTTP MCP endpoint (empty = generate)")
	pprofAddr := flag.String("pprof-addr", env("EBPFSHARK_PPROF_ADDR", ""), "optional local profiling address, e.g. 127.0.0.1:6060")
	tlsKeylog := flag.String("tls-keylog", env("EBPFSHARK_TLS_KEYLOG", env("SSLKEYLOGFILE", "")), "NSS SSLKEYLOGFILE for TLS 1.2/1.3 decryption")
	tlsKeylogAuto := flag.Bool("tls-keylog-auto", envBool("EBPFSHARK_TLS_KEYLOG_AUTO", true), "discover and watch SSLKEYLOGFILE from running processes")
	plugins := flag.String("plugins", env("EBPFSHARK_PLUGINS", ""), "comma separated Go .so dissector plugins")
	cgroup := flag.String("cgroup", env("EBPFSHARK_CGROUP", ""), "capture only sockets in a cgroup: ID, path, pid:N, pod:NAME or container:ID")
	captureFilter := flag.String("capture-filter", env("EBPFSHARK_CAPTURE_FILTER", ""), "display filter whose safe L2-L4 subset is applied in eBPF")
	pluginDir := flag.String("plugin-dir", env("EBPFSHARK_PLUGIN_DIR", ""), "directory containing .so dissector plugins")
	sshKeys := flag.String("ssh-keys", env("EBPFSHARK_SSH_KEYS", ""), "JSON session keys for opt-in SSH AES-CTR decryption")
	wifiPSK := flag.String("wifi-psk", env("EBPFSHARK_WIFI_PSK", ""), "WPA2-PSK passphrase for CCMP frame decryption")
	wifiKeys := flag.String("wifi-keys", env("EBPFSHARK_WIFI_KEYS", ""), "JSON PMK/PTK session keys for WPA2/WPA3 (missing handshake)")
	mitmAddr := flag.String("mitm", env("EBPFSHARK_MITM", "127.0.0.1:18080"), "local HTTPS MITM proxy address (empty disables)")
	mitmCADir := flag.String("mitm-ca-dir", env("EBPFSHARK_MITM_CA_DIR", defaultMITMCADir()), "directory for the MITM CA certificate and key")
	noMCP := flag.Bool("no-mcp", false, "disable the HTTP MCP endpoint")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	log := newLogger(*logLevel)
	if *showVersion {
		fmt.Printf("ebpfshark %s\n", server.Version)
		return
	}
	if *pprofAddr != "" {
		go func() {
			log.Warn("pprof endpoint enabled", "addr", *pprofAddr)
			if err := http.ListenAndServe(*pprofAddr, nil); err != nil {
				log.Error("pprof server stopped", "err", err)
			}
		}()
	}
	if *wifiPSK != "" {
		decode.LoadWiFiPSK(*wifiPSK)
		log.Info("WPA2-PSK decryption enabled")
	}
	if *wifiKeys != "" {
		if err := decode.LoadWiFiKeys(*wifiKeys); err != nil {
			log.Warn("load Wi-Fi keys failed", "path", *wifiKeys, "err", err)
		} else {
			log.Info("loaded Wi-Fi session keys", "path", *wifiKeys)
		}
	}
	if *sshKeys != "" {
		if err := decode.LoadSSHKeys(*sshKeys); err != nil {
			log.Warn("load SSH keys failed", "path", *sshKeys, "err", err)
		} else {
			log.Info("loaded SSH session keys", "path", *sshKeys)
		}
	}
	if pluginPaths := collectPluginPaths(*plugins, *pluginDir); len(pluginPaths) > 0 {
		if err := decode.LoadDynamicPlugins(pluginPaths); err != nil {
			log.Error("load dynamic plugins failed", "err", err)
		} else {
			log.Info("loaded dynamic plugins", "count", len(pluginPaths))
		}
	}
	if *tlsKeylog != "" {
		if err := decode.LoadKeyLog(*tlsKeylog); err != nil {
			log.Warn("load TLS keylog failed", "path", *tlsKeylog, "err", err)
		} else {
			log.Info("loaded TLS keylog", "path", *tlsKeylog)
		}
	}

	var targetFilter filter.CaptureSpec
	if *captureFilter != "" {
		spec, err := filter.CompileCapture(*captureFilter)
		if err != nil {
			log.Error("compile capture filter failed", "filter", *captureFilter, "err", err)
			os.Exit(1)
		}
		targetFilter = spec
	}
	var targetCgroup uint64
	if *cgroup != "" {
		id, err := capture.ResolveCgroup(*cgroup)
		if err != nil {
			log.Error("resolve cgroup failed", "cgroup", *cgroup, "err", err)
			os.Exit(1)
		}
		targetCgroup = id
		log.Info("capture cgroup filter enabled", "cgroupID", id)
	}

	var webFS fs.FS
	var err error
	if *webDir != "" {
		webFS = os.DirFS(*webDir)
	} else {
		webFS, err = server.WebFS()
		if err != nil {
			log.Error("open embedded web assets", "err", err)
			os.Exit(1)
		}
	}

	selfPort := uint16(0)
	if *excludeSelf {
		selfPort = listenPort(*addr)
	}

	authEnabled := !*noAuth
	authPassValue := *authPass
	if authEnabled && authPassValue == "" {
		generated, err := auth.GeneratePassword()
		if err != nil {
			log.Error("generate password failed", "err", err)
			os.Exit(1)
		}
		authPassValue = generated
		fmt.Fprintf(os.Stderr,
			"\n  ebpfshark login credentials (generated for this run):\n    username: %s\n    password: %s\n  Set EBPFSHARK_AUTH_PASS to use a stable password.\n\n",
			*authUser, authPassValue)
	}
	if authEnabled && *authUser == "" {
		log.Error("auth-user must not be empty")
		os.Exit(1)
	}
	if authEnabled && len(authPassValue) < 8 {
		log.Warn("authentication password is shorter than 8 characters")
	}
	if !authEnabled {
		log.Warn("authentication is DISABLED (-no-auth); anyone who can reach this port can read captures")
	}
	authSvc := auth.New(*authUser, authPassValue, authEnabled, *authTTL)

	st := store.New(*maxPackets)
	st.SetStreamBudget(int64(*streamBudget) << 20)
	mgr := capture.NewManager(st, log)
	var mitmProxy *mitm.Proxy
	if *mitmAddr != "" {
		proxy, err := mitm.New(mitm.Config{Addr: *mitmAddr, CADir: *mitmCADir, Store: st, Logger: log})
		if err != nil {
			log.Error("initialize MITM proxy failed", "err", err)
		} else if err := proxy.Start(); err != nil {
			log.Warn("start MITM proxy failed; trying another loopback port", "addr", *mitmAddr, "err", err)
			started := false
			for port := 18081; port <= 18099; port++ {
				if err := proxy.Reconfigure(fmt.Sprintf("127.0.0.1:%d", port)); err == nil {
					started = true
					break
				}
			}
			if !started {
				log.Error("start MITM proxy failed", "err", err)
			} else {
				mitmProxy = proxy
				defer proxy.Close()
			}
		} else {
			mitmProxy = proxy
			defer proxy.Close()
		}
	}
	srv := server.New(st, mgr, log, webFS, selfPort, authSvc)
	srv.SetMITM(mitmProxy)
	srv.SetSecureCookie(*secureCookie)
	defer srv.StopTrace()

	mcpEnabled := !*noMCP
	if mcpEnabled {
		token := *mcpToken
		if token == "" {
			generated, err := auth.GeneratePassword()
			if err != nil {
				log.Error("generate MCP token failed", "err", err)
				os.Exit(1)
			}
			token = generated
			fmt.Fprintf(os.Stderr,
				"\n  MCP HTTP endpoint enabled at /mcp\n    Authorization: Bearer %s\n  Set EBPFSHARK_MCP_TOKEN to use a stable token.\n\n",
				token)
		}
		mcpSrv := mcpserver.New(st, mgr, server.Version, uint32(selfPort), srv)
		srv.SetMCPHandler(mcpserver.HTTPHandler(mcpSrv, token))
	}

	httpServer := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	decode.SetKeyLogAuto(*tlsKeylogAuto)
	// Keep the watcher alive even when discovery is disabled: the Web UI can
	// enable it at runtime. Explicit -tls-keylog paths are still watched.
	go decode.WatchKeyLogs(ctx, *tlsKeylog, 5*time.Second)

	updater := update.New(update.Config{
		Enabled:        *autoUpdate,
		Interval:       *updateInterval,
		ManifestURL:    *updateURL,
		CurrentVersion: server.Version,
		Logger:         log,
		CanUpdate:      func() bool { return !mgr.Status().Running },
		Restart: func() {
			log.Warn("restarting to apply auto-update")
			mgr.Stop()
			exe, err := os.Executable()
			if err != nil {
				log.Error("auto-update restart failed", "err", err)
				return
			}
			if err := syscall.Exec(exe, os.Args, os.Environ()); err != nil {
				log.Error("auto-update exec failed; restart manually", "err", err)
			}
		},
	})
	srv.SetUpdateStatus(func() any { return updater.Status() })
	updater.Start(ctx)

	if *iface != "" {
		names := splitNames(*iface)
		if err := mgr.Start(capture.Options{
			Interfaces:    names,
			Snaplen:       uint32(*snaplen),
			SampleRate:    uint32(*sampleRate),
			RingSize:      uint32(*ringSize),
			ExcludePort:   uint32(selfPort),
			CgroupID:      targetCgroup,
			CaptureFilter: targetFilter,
		}); err != nil {
			log.Error("auto-start capture failed", "err", err)
		}
	}

	go func() {
		<-ctx.Done()
		log.Info("shutting down")
		mgr.Stop()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
	}()

	log.Info("ebpfshark listening", "addr", *addr, "version", server.Version,
		"maxPackets", *maxPackets, "excludePort", selfPort,
		"authEnabled", authEnabled, "authUser", *authUser, "authTTL", authTTL.String(),
		"streamBudgetMB", *streamBudget, "mcpEnabled", mcpEnabled,
		"autoUpdate", *autoUpdate, "updateInterval", updateInterval.String(), "updateURL", *updateURL)
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("http server failed", "err", err)
		os.Exit(1)
	}
}

// runMCPStdio runs the MCP server over stdin/stdout for local MCP clients.
// Logs go to stderr so stdout stays a clean JSON-RPC stream.
func runTrace(args []string) {
	fs := flag.NewFlagSet("trace", flag.ExitOnError)
	pid := fs.Int("pid", 0, "trace only this PID (0 = all processes loading the binary)")
	functions := fs.String("func", "", "comma separated binary:symbol uprobe targets")
	duration := fs.Duration("duration", 0, "stop after this duration (0 = until Ctrl-C)")
	inspectOnly := fs.Bool("inspect", false, "inspect the target ELF for build-id/symbols/debuginfo and exit")
	_ = fs.Parse(args)
	if *functions == "" {
		fmt.Fprintln(os.Stderr, "usage: ebpfshark trace -pid PID -func /path/to/bin:symbol[,binary:symbol...]")
		os.Exit(2)
	}
	fns, err := probe.ParseFunctions(*functions)
	if err != nil {
		fmt.Fprintln(os.Stderr, "invalid -func:", err)
		os.Exit(2)
	}
	if *pid < 0 {
		fmt.Fprintln(os.Stderr, "invalid -pid")
		os.Exit(2)
	}
	if *inspectOnly {
		binary := ""
		if len(fns) > 0 {
			binary = fns[0].Binary
		}
		info, ierr := probe.Inspect(*pid, binary)
		if ierr != nil {
			fmt.Fprintln(os.Stderr, "inspect:", ierr)
			os.Exit(1)
		}
		fmt.Printf("path: %s\nbuild-id: %s\nstripped: %v\nsymbols: %d\ndebuginfo: %s\ndebuginfod: %v\n",
			info.Path, info.BuildID, info.Stripped, info.Symbols, info.DebugFile, info.Debuginfod)
		for _, s := range info.Suggestions {
			fmt.Println("suggestion:", s)
		}
		return
	}
	tracer, err := probe.Start(probe.Options{PID: *pid, Functions: fns})
	if err != nil {
		fmt.Fprintln(os.Stderr, "start trace:", err)
		binary := ""
		if len(fns) > 0 {
			binary = fns[0].Binary
		}
		if info, ierr := probe.Inspect(*pid, binary); ierr == nil {
			fmt.Fprintf(os.Stderr, "target: %s build-id=%s stripped=%v symbols=%d\n", info.Path, info.BuildID, info.Stripped, info.Symbols)
			for _, s := range info.Suggestions {
				fmt.Fprintln(os.Stderr, "  -", s)
			}
		}
		os.Exit(1)
	}
	defer tracer.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var timer <-chan time.Time
	if *duration > 0 {
		t := time.NewTimer(*duration)
		defer t.Stop()
		timer = t.C
	}
	fmt.Fprintf(os.Stderr, "tracing %d function(s) pid=%d (Ctrl-C to stop)\n", len(fns), *pid)
	for {
		select {
		case ev, ok := <-tracer.Events():
			if !ok {
				return
			}
			fmt.Printf("%s %-28s pid=%d tid=%d dur=%s comm=%s\n",
				ev.Time.Format("15:04:05.000000"), ev.Function, ev.PID, ev.TID, ev.Duration, ev.Comm)
		case <-timer:
			return
		case <-ctx.Done():
			return
		}
	}
}

func runMCPStdio(args []string) {
	fs := flag.NewFlagSet("mcp", flag.ExitOnError)
	maxPackets := fs.Int("max-packets", envInt("EBPFSHARK_MAX_PACKETS", 100000), "packets kept in the ring buffer")
	streamBudget := fs.Int("stream-budget", envInt("EBPFSHARK_STREAM_BUDGET", 64), "TCP reassembly memory budget in MiB")
	logLevel := fs.String("log-level", env("EBPFSHARK_LOG_LEVEL", "warn"), "debug, info, warn or error")
	excludePort := fs.Uint("exclude-port", 0, "TCP/UDP port to exclude from captures (0 = none)")
	plugins := fs.String("plugins", env("EBPFSHARK_PLUGINS", ""), "comma separated Go .so dissector plugins")
	pluginDir := fs.String("plugin-dir", env("EBPFSHARK_PLUGIN_DIR", ""), "directory containing .so dissector plugins")
	_ = fs.Parse(args)

	log := newLogger(*logLevel)
	if paths := collectPluginPaths(*plugins, *pluginDir); len(paths) > 0 {
		if err := decode.LoadDynamicPlugins(paths); err != nil {
			log.Error("load dynamic plugins failed", "err", err)
		} else {
			log.Info("loaded dynamic plugins", "count", len(paths))
		}
	}
	st := store.New(*maxPackets)
	st.SetStreamBudget(int64(*streamBudget) << 20)
	mgr := capture.NewManager(st, log)
	srv := mcpserver.New(st, mgr, server.Version, uint32(*excludePort))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Info("MCP stdio server started", "version", server.Version)
	if err := srv.Run(ctx, &mcp.StdioTransport{}); err != nil {
		log.Error("MCP stdio server failed", "err", err)
		os.Exit(1)
	}
}

// listenPort extracts the TCP port from a listen address such as ":9999" or
// "127.0.0.1:9999". It returns 0 when the port cannot be determined.
func listenPort(addr string) uint16 {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	n, err := strconv.Atoi(port)
	if err != nil || n <= 0 || n > 65535 {
		return 0
	}
	return uint16(n)
}

func splitNames(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	switch strings.ToLower(level) {
	case "debug":
		l = slog.LevelDebug
	case "warn":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envBool(key string, def bool) bool {
	if v := os.Getenv(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func collectPluginPaths(list, dir string) []string {
	var out []string
	for _, p := range strings.Split(list, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	if dir != "" {
		for _, pattern := range []string{"*.so", "*.dylib"} {
			matches, _ := filepath.Glob(filepath.Join(dir, pattern))
			out = append(out, matches...)
		}
	}
	return out
}
