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
	Comm       string `json:"comm"`
	CgroupID   uint64 `json:"cgroupID,omitempty"`
	CgroupPath string `json:"cgroupPath,omitempty"`
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
		if needle != "" &&
			!strings.Contains(strings.ToLower(comm), needle) &&
			!strings.Contains(strings.ToLower(path), needle) &&
			!strings.Contains(strconv.Itoa(pid), needle) {
			continue
		}
		processes = append(processes, ProcessInfo{
			PID: pid, Comm: comm, CgroupID: id, CgroupPath: path,
		})
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
