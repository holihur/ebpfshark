package capture

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// ResolveCgroup resolves a cgroup v2 identifier for -cgroup:
//
//	12345                 cgroup inode/id
//	/sys/fs/cgroup/...    cgroup filesystem path
//	path:/sys/fs/cgroup/. ..
//	pid:1234              process's current cgroup
//	pod:<fragment>        first cgroup path containing the fragment
//	container:<fragment>  same search, for container runtimes
//
// The eBPF program compares the socket's cgroup id, so this scopes capture to
// sockets created in that cgroup (including its descendants), rather than by
// guessing ports.
func ResolveCgroup(spec string) (uint64, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return 0, nil
	}
	switch {
	case strings.HasPrefix(spec, "pid:"):
		return cgroupIDForPID(strings.TrimSpace(strings.TrimPrefix(spec, "pid:")))
	case strings.HasPrefix(spec, "path:"):
		return cgroupIDFromPath(strings.TrimPrefix(spec, "path:"))
	case strings.HasPrefix(spec, "pod:"):
		return findCgroupByFragment(strings.TrimPrefix(spec, "pod:"))
	case strings.HasPrefix(spec, "container:"):
		return findCgroupByFragment(strings.TrimPrefix(spec, "container:"))
	}
	if n, err := strconv.ParseUint(spec, 10, 64); err == nil {
		return n, nil
	}
	if strings.HasPrefix(spec, "/") {
		return cgroupIDFromPath(spec)
	}
	return 0, fmt.Errorf("invalid cgroup %q (use ID, path, pid:N, pod:NAME or container:ID)", spec)
}

func cgroupIDFromPath(p string) (uint64, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return 0, fmt.Errorf("empty cgroup path")
	}
	if !strings.HasPrefix(p, "/sys/fs/cgroup") {
		p = filepath.Join("/sys/fs/cgroup", strings.TrimPrefix(p, "/"))
	}
	info, err := os.Stat(p)
	if err != nil {
		return 0, err
	}
	if !info.IsDir() {
		return 0, fmt.Errorf("%s is not a cgroup directory", p)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("cannot read cgroup inode for %s", p)
	}
	return st.Ino, nil
}

func cgroupIDForPID(pid string) (uint64, error) {
	if pid == "" {
		return 0, fmt.Errorf("empty PID")
	}
	if _, err := strconv.Atoi(pid); err != nil {
		return 0, fmt.Errorf("invalid PID %q", pid)
	}
	data, err := os.ReadFile(filepath.Join("/proc", pid, "cgroup"))
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "0::") {
			path := strings.TrimPrefix(line, "0::")
			if path == "" {
				path = "/"
			}
			return cgroupIDFromPath(filepath.Join("/sys/fs/cgroup", path))
		}
	}
	return 0, fmt.Errorf("PID %s has no cgroup v2 entry (cgroup v1 is unsupported)", pid)
}

func findCgroupByFragment(fragment string) (uint64, error) {
	fragment = strings.TrimSpace(fragment)
	if fragment == "" {
		return 0, fmt.Errorf("empty pod/container fragment")
	}
	var found uint64
	var foundPath string
	visits := 0
	err := filepath.WalkDir("/sys/fs/cgroup", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		visits++
		if visits > 100000 {
			return fs.SkipAll
		}
		if strings.Contains(filepath.Base(path), fragment) {
			if id, err := cgroupIDFromPath(path); err == nil {
				found, foundPath = id, path
				return fs.SkipAll
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	if found == 0 {
		return 0, fmt.Errorf("no cgroup matching %q under /sys/fs/cgroup", fragment)
	}
	_, _ = fmt.Fprintln(os.Stderr, "resolved cgroup", fragment, "to", foundPath)
	return found, nil
}
