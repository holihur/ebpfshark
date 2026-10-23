package capture

import (
	"os"
	"strconv"
	"testing"
)

func TestResolveCgroupNumericAndPath(t *testing.T) {
	id, err := ResolveCgroup("12345")
	if err != nil || id != 12345 {
		t.Fatalf("id=%d err=%v", id, err)
	}
	if _, err := ResolveCgroup("not-a-cgroup"); err == nil {
		t.Fatal("expected error")
	}
	if _, err := ResolveCgroup("/sys/fs/cgroup"); err != nil {
		t.Fatalf("root cgroup: %v", err)
	}
}

func TestResolveCgroupPID(t *testing.T) {
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err != nil {
		t.Skip("cgroup v2 not available")
	}
	id, err := ResolveCgroup("pid:" + strconv.Itoa(os.Getpid()))
	if err != nil || id == 0 {
		t.Fatalf("id=%d err=%v", id, err)
	}
}
