package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go lb_sticky_rr_v1 ../bpf/lb_sticky_rr_v1.c




func main() {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}


	loadBalancerType := os.Getenv("LOAD_BALANCER_TYPE")
	fmt.Println("Load Balancer Type: ", loadBalancerType)
	switch loadBalancerType {
	case "Sticky_RR_v1":
		 runLoadBalancerV1()
	// case "Sticky_RR_v2":
	// 	runLoadBalancerV2()
	// case "Sticky_RR_v3":
	// 	runLoadBalancerV3()
	default:
		log.Fatalf("unknown load balancer type: %s", loadBalancerType)
	}

	// Handle Ctrl+C (SIGINT) to gracefully exit
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	// Channel to signal the reading goroutine to stop
	done := make(chan struct{})

	// Start a goroutine to read from the ebpf dropped map
	go readEBPFMap(done)

	// Block until a signal is received
	fmt.Println("Press Ctrl+C to exit...")
	<-sigs

	// Signal the goroutine to stop reading
	close(done)

	// We can give the goroutine a moment to finish
	time.Sleep(100 * time.Millisecond)

}

func ipToInt(ipStr string) (uint32, error) {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return 0, fmt.Errorf("invalid IPv4 address")
	}
	return binary.BigEndian.Uint32(ip), nil
}

func readEBPFMap(done chan struct{}) {
	// Periodically read the value from the counter map and log it.
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			fmt.Println("Stopping reading from eBPF map.")
			return // Exit the goroutine
		case <-ticker.C:
			log.Println("Reading from eBPF map...")
		}
	}
}

func runLoadBalancerV1() link.Link{
	// Load the eBPF program and maps into the kernel.
	objs := lb_sticky_rr_v1Objects{}
	if err := loadLb_sticky_rr_v1Objects(&objs, nil); err != nil {
		log.Fatalf("loading lb_sticky_rr_v1 objects: %v", err)
	}

	if err := objs.lb_sticky_rr_v1Variables.CurrentBackendIndex.Set(0); err != nil {
		log.Fatalf("setting lb_v1Variables CurrentBackendIndex (Err: %v)", err)
	}

	// populate BPF map
	ipAddresses := [3]string{"10.0.1.2", "10.0.2.2", "10.0.3.2"}
	for i,ip := range ipAddresses {
		ipValue, err := ipToInt(ip)
		if err != nil {
			log.Fatalf("converting string to IP (Err: %v)", err)
		}
		if err := objs.lb_sticky_rr_v1Maps.Backends.Put(&i, ipValue); err != nil {
			log.Fatalf("setting lb_v1Maps.Backends (Err: %v)", err)
		}
	}
	
	
	// Attach the program to Ingress TC.
	l, err := link.AttachTCX(link.TCXOptions{
		Interface: ingress.Index,
		Program:   objs.lb_sticky_rr_v1Programs.LoadBalancerRrV1,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		log.Fatalf("could not attach TCx program: %s", err)
	}

	return l

}




// func runLoadBalancerV2() {
// 	objs := lb_sticky_rr_v2Objects{}
// 	if err := loadLb_sticky_rr_v1Objects(&objs, nil); err != nil {
// 		log.Fatalf("loading lb_lb_sticky_rr_v2 objects: %v", err)
// 	}

// 	fmt.Println("Sticky Round Robin Load Balancer V2 started")
// }

// func runLoadBalancerV3() {
// 	objs := lb_sticky_rr_v3Objects{}
// 	if err := loadLb_sticky_rr_v3Objects(&objs, nil); err != nil {
// 		log.Fatalf("loading lb_lb_sticky_rr_v3 objects: %v", err)
// 	}
// 	fmt.Println("Sticky Round Robin Load Balancer V3 started")
// }