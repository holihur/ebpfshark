package capture

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel -cflags "-O2 -g -Wall -Wno-unused-function -Ibpf" capture bpf/capture.c

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel -cflags "-O2 -g -Wall -DCAPTURE_LARGE -I../../capture/bpf" capture_large bpf/capture.c
