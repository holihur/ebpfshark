// Package ipc contains the Unix-domain-socket inventory and event model.
// Payload tracing is a separate eBPF backend; this package intentionally does
// not depend on the network capture/store packages.
package ipc

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Socket is one entry from /proc/net/unix, enriched with the owning process
// when it can be resolved from /proc/<pid>/fd.
type Socket struct {
	Inode  uint64 `json:"inode"`
	Path   string `json:"path,omitempty"`
	Type   string `json:"type"`
	State  string `json:"state,omitempty"`
	PID    int    `json:"pid,omitempty"`
	Comm   string `json:"comm,omitempty"`
	Exe    string `json:"exe,omitempty"`
	Cgroup string `json:"cgroupPath,omitempty"`
}

// ListSockets enumerates Unix sockets and resolves inode owners on a best-effort
// basis. Sockets that disappear during the scan are skipped.
func ListSockets() ([]Socket, error) {
	f, err := os.Open("/proc/net/unix")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	owners := socketOwners()
	var out []Socket
	sc := bufio.NewScanner(f)
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 8 {
			continue
		}
		inode, err := strconv.ParseUint(fields[6], 10, 64)
		if err != nil || inode == 0 {
			continue
		}
		s := Socket{
			Inode: inode,
			Type:  udsType(fields[4]),
			State: udsState(fields[5]),
			Path:  strings.Join(fields[7:], " "),
		}
		if owner, ok := owners[inode]; ok {
			s.PID, s.Comm, s.Exe, s.Cgroup = owner.pid, owner.comm, owner.exe, owner.cgroup
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Inode < out[j].Inode
	})
	return out, sc.Err()
}

type owner struct {
	pid    int
	comm   string
	exe    string
	cgroup string
}

func socketOwners() map[uint64]owner {
	owners := make(map[uint64]owner)
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return owners
	}
	for _, entry := range entries {
		if !entry.IsDir() || entry.Name()[0] < '0' || entry.Name()[0] > '9' {
			continue
		}
		dir := filepath.Join("/proc", entry.Name())
		fds, _ := os.ReadDir(filepath.Join(dir, "fd"))
		if len(fds) == 0 {
			continue
		}
		comm, _ := os.ReadFile(filepath.Join(dir, "comm"))
		exe, _ := os.Readlink(filepath.Join(dir, "exe"))
		cg, _ := os.ReadFile(filepath.Join(dir, "cgroup"))
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(dir, "fd", fd.Name()))
			if err != nil || !strings.HasPrefix(target, "socket:[") {
				continue
			}
			ino, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]"), 10, 64)
			if err != nil || ino == 0 {
				continue
			}
			path := cgroupPath(string(cg))
			if _, exists := owners[ino]; !exists {
				pid, _ := strconv.Atoi(entry.Name())
				owners[ino] = owner{pid: pid, comm: strings.TrimSpace(string(comm)), exe: strings.TrimSuffix(exe, " (deleted)"), cgroup: path}
			}
		}
	}
	return owners
}

func cgroupPath(data string) string {
	for _, line := range strings.Split(data, "\n") {
		if strings.HasPrefix(line, "0::") {
			return strings.TrimPrefix(line, "0::")
		}
	}
	return ""
}

func udsType(v string) string {
	n, _ := strconv.ParseUint(v, 8, 32)
	switch n {
	case 1:
		return "stream"
	case 2:
		return "dgram"
	case 5:
		return "seqpacket"
	default:
		return "type-" + v
	}
}

func udsState(v string) string {
	n, _ := strconv.ParseUint(v, 16, 32)
	switch n {
	case 1:
		return "listening"
	case 2:
		return "connecting"
	case 3:
		return "connected"
	default:
		return ""
	}
}

func socketTypeName(code uint8) string {
	switch code {
	case 1:
		return "stream"
	case 2:
		return "dgram"
	case 5:
		return "seqpacket"
	default:
		return ""
	}
}
