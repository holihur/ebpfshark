package ipc

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel -cflags "-O2 -g -Wall -I../capture/bpf" uds bpf/uds.c
