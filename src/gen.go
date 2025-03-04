package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux lb_v1 ../bpf/lb_sticky_rr_v1.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux lb_v2 ../bpf/lb_sticky_rr_v2.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux lb_v3 ../bpf/lb_sticky_rr_v3.c


