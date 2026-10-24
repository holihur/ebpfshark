package capture

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// ProcessInfo is a process together with its cgroup v2 identity. It is used by
// the UI to scope a capture to a process without requiring the user to look up
// inode numbers manually.
type ProcessInfo struct {
	PID        int    `json:"pid"`
	PPID       int    `json:"ppid,omitempty"`
	Comm       string `json:"comm"`
	State      string `json:"state,omitempty"`
	Threads    int    `json:"threads,omitempty"`
	RSS        uint64 `json:"rss,omitempty"`
	VSize      uint64 `json:"vsize,omitempty"`
	CgroupID   uint64 `json:"cgroupID,omitempty"`
	CgroupPath string `json:"cgroupPath,omitempty"`
	Command    string `json:"command,omitempty"`
	Exe        string `json:"exe,omitempty"`
}

// ListProcesses enumerates /proc and resolves each process's cgroup v2 path and
// inode. Processes that exit during the scan are skipped. query is a
// case-insensitive match over comm, path and PID.
func ListProcesses(query string, limit int) ([]ProcessInfo, error) {
	if limit <= 0 {
		limit = 300
	}
	if limit > 2000 {
		limit = 2000
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	needle := strings.ToLower(strings.TrimSpace(query))
	processes := make([]ProcessInfo, 0, 64)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		commBytes, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "comm"))
		if err != nil {
			continue
		}
		comm := strings.TrimSpace(string(commBytes))
		cgroupBytes, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cgroup"))
		if err != nil {
			continue
		}
		path, id := parseCgroupV2(string(cgroupBytes))
		if id == 0 {
			continue
		}
		info := ProcessInfo{PID: pid, Comm: comm, CgroupID: id, CgroupPath: path}
		parseProcStat(pid, &info)
		if cmd, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline")); err == nil {
			info.Command = strings.TrimSpace(strings.ReplaceAll(string(cmd), "\x00", " "))
		}
		if exe, err := os.Readlink(filepath.Join("/proc", entry.Name(), "exe")); err == nil {
			info.Exe = strings.TrimSuffix(exe, " (deleted)")
		}
		if needle != "" &&
			!strings.Contains(strings.ToLower(comm), needle) &&
			!strings.Contains(strings.ToLower(path), needle) &&
			!strings.Contains(strings.ToLower(info.Command), needle) &&
			!strings.Contains(strings.ToLower(info.Exe), needle) &&
			!strings.Contains(strconv.Itoa(pid), needle) {
			continue
		}
		processes = append(processes, info)
	}
	sort.Slice(processes, func(i, j int) bool {
		if processes[i].Comm != processes[j].Comm {
			return processes[i].Comm < processes[j].Comm
		}
		return processes[i].PID < processes[j].PID
	})
	if len(processes) > limit {
		processes = processes[:limit]
	}
	return processes, nil
}

func parseCgroupV2(data string) (path string, id uint64) {
	for _, line := range strings.Split(data, "\n") {
		if !strings.HasPrefix(line, "0::") {
			continue
		}
		path = strings.TrimPrefix(line, "0::")
		if path == "" {
			path = "/"
		}
		id, _ = cgroupIDFromPath(path)
		return path, id
	}
	return "", 0
}

func parseProcStat(pid int, info *ProcessInfo) {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return
	}
	// comm may contain spaces and parentheses; fields after the closing ')'.
	end := strings.LastIndexByte(string(data), ')')
	if end < 0 || end+2 >= len(data) {
		return
	}
	fields := strings.Fields(string(data[end+2:]))
	if len(fields) < 22 {
		return
	}
	info.State = fields[0]
	if v, err := strconv.Atoi(fields[1]); err == nil {
		info.PPID = v
	}
	if v, err := strconv.Atoi(fields[17]); err == nil {
		info.Threads = v
	}
	if v, err := strconv.ParseUint(fields[20], 10, 64); err == nil {
		info.VSize = v
	}
	if v, err := strconv.ParseUint(fields[21], 10, 64); err == nil {
		info.RSS = v * uint64(os.Getpagesize())
	}
}
