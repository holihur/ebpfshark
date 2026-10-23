package probe

import (
	"bytes"
	"debug/elf"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Info describes what can be discovered about a trace target. It is used by
// the API/UI assist flow when a symbol cannot be resolved.
type Info struct {
	PID         int      `json:"pid"`
	Path        string   `json:"path"`
	BuildID     string   `json:"buildId,omitempty"`
	Stripped    bool     `json:"stripped"`
	Symbols     int      `json:"symbols"`
	DebugFile   string   `json:"debugFile,omitempty"`
	Debuginfod  bool     `json:"debuginfod"`
	Comm        string   `json:"comm,omitempty"`
	CgroupPath  string   `json:"cgroupPath,omitempty"`
	ContainerID string   `json:"containerId,omitempty"`
	PodUID      string   `json:"podUid,omitempty"`
	Suggestions []string `json:"suggestions"`
}

// Inspect resolves PID/exe and inspects ELF symbols and local debuginfo.
func Inspect(pid int, binary string) (Info, error) {
	info := Info{PID: pid, Path: binary}
	if info.Path == "" && pid > 0 {
		p, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
		if err != nil {
			return info, err
		}
		info.Path = strings.TrimSuffix(p, " (deleted)")
	}
	if info.Path == "" {
		return info, fmt.Errorf("binary or PID is required")
	}
	if pid > 0 {
		if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid)); err == nil {
			info.Comm = strings.TrimSpace(string(b))
		}
		info.CgroupPath, info.ContainerID, info.PodUID = inspectCgroup(pid)
	}
	f, err := elf.Open(info.Path)
	if err != nil {
		return info, err
	}
	defer f.Close()
	info.BuildID = elfBuildID(f)
	info.Stripped = f.Section(".symtab") == nil
	if syms, err := f.Symbols(); err == nil {
		info.Symbols = len(syms)
	}
	info.DebugFile = findDebugFile(info.Path, info.BuildID)
	if os.Getenv("DEBUGINFOD_URLS") != "" {
		info.Debuginfod = true
	}
	if info.Symbols == 0 {
		info.Suggestions = append(info.Suggestions,
			"install distro debuginfo/dbgsym package",
			"use an unstripped binary",
			"provide an explicit address with binary:@0xOFFSET",
		)
	} else {
		info.Suggestions = append(info.Suggestions, "use binary:symbol or binary:0xADDRESS")
	}
	if info.DebugFile != "" {
		info.Suggestions = append(info.Suggestions, "debuginfo found: "+info.DebugFile)
	}
	return info, nil
}

func elfBuildID(f *elf.File) string {
	sec := f.Section(".note.gnu.build-id")
	if sec == nil {
		return ""
	}
	data, err := sec.Data()
	if err != nil {
		return ""
	}
	for len(data) >= 12 {
		namesz := int(f.ByteOrder.Uint32(data[0:4]))
		descsz := int(f.ByteOrder.Uint32(data[4:8]))
		typ := f.ByteOrder.Uint32(data[8:12])
		off := 12
		if namesz < 0 || descsz < 0 || off+namesz+descsz > len(data) {
			break
		}
		if typ == 3 {
			return hex.EncodeToString(data[off+namesz : off+namesz+descsz])
		}
		pad := (4 - (namesz+descsz)%4) % 4
		data = data[off+namesz+descsz+pad:]
	}
	return ""
}

func findDebugFile(binary, buildID string) string {
	if buildID != "" && len(buildID) >= 2 {
		p := filepath.Join("/usr/lib/debug/.build-id", buildID[:2], buildID[2:]+".debug")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	f, err := elf.Open(binary)
	if err != nil {
		return ""
	}
	defer f.Close()
	sec := f.Section(".gnu_debuglink")
	if sec == nil {
		return ""
	}
	data, err := sec.Data()
	if err != nil {
		return ""
	}
	i := bytes.IndexByte(data, 0)
	if i <= 0 {
		return ""
	}
	name := string(data[:i])
	for _, root := range []string{"/usr/lib/debug", "/usr/local/lib/debug"} {
		p := filepath.Join(root, filepath.Dir(binary), name)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

var (
	containerIDRE = regexp.MustCompile(`(?:docker-|cri-containerd-|libpod-|containerd-)?([0-9a-f]{64})(?:\.scope)?`)
	podUIDRE      = regexp.MustCompile(`pod([0-9a-fA-F-]{32,36})`)
)

func inspectCgroup(pid int) (path, container, pod string) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", "", ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "0::") {
			continue
		}
		path = strings.TrimPrefix(line, "0::")
		if m := containerIDRE.FindStringSubmatch(path); len(m) > 1 {
			container = m[1]
		}
		if m := podUIDRE.FindStringSubmatch(path); len(m) > 1 {
			pod = m[1]
		}
		return path, container, pod
	}
	return "", "", ""
}
