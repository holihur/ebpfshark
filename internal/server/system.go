package server

import (
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SystemInfo is the small, unprivileged host summary shown in the UI header.
type SystemInfo struct {
	Kernel        string `json:"kernel,omitempty"`
	OS            string `json:"os,omitempty"`
	Hostname      string `json:"hostname,omitempty"`
	MemoryTotal   uint64 `json:"memoryTotal"`
	MemoryAvail   uint64 `json:"memoryAvailable"`
	UptimeSeconds uint64 `json:"uptimeSeconds"`
}

var systemCache struct {
	sync.Mutex
	at   time.Time
	info SystemInfo
}

func currentSystemInfo() SystemInfo {
	systemCache.Lock()
	if time.Since(systemCache.at) < 2*time.Second && systemCache.info.Kernel != "" {
		info := systemCache.info
		systemCache.Unlock()
		return info
	}
	systemCache.Unlock()

	info := SystemInfo{}
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		info.Kernel = strings.TrimSpace(string(b))
	}
	if b, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				info.OS = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"'`)
				break
			}
		}
	}
	info.Hostname, _ = os.Hostname()
	for _, line := range strings.Split(readText("/proc/meminfo"), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		v, _ := strconv.ParseUint(fields[1], 10, 64)
		switch fields[0] {
		case "MemTotal:":
			info.MemoryTotal = v * 1024
		case "MemAvailable:":
			info.MemoryAvail = v * 1024
		}
	}
	if fields := strings.Fields(readText("/proc/uptime")); len(fields) > 0 {
		if f, err := strconv.ParseFloat(fields[0], 64); err == nil {
			info.UptimeSeconds = uint64(f)
		}
	}
	systemCache.Lock()
	systemCache.at = time.Now()
	systemCache.info = info
	systemCache.Unlock()
	return info
}

func readText(path string) string {
	b, _ := os.ReadFile(path)
	return string(b)
}
