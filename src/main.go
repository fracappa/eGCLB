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

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go lb_sticky_rr_v1 ../bpf/lb_sticky_rr_v1.c

type BackendAddr struct {
    IP  uint32   // 4 bytes
    MAC [6]byte  // 6 bytes
    Pad [3]byte  // explicit padding to reach 13 bytes total
}



func main() {

	if len(os.Args) < 2 {
		log.Fatalf("Please specify a network interface")
	}

	// Look up the network interface by name.
	ifaceName := os.Args[1]
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", ifaceName, err)
	}
	

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	loadBalancerType := os.Getenv("LOAD_BALANCER_TYPE")
	fmt.Println("Load Balancer Type: ", loadBalancerType)
	runLoadBalancerV1(iface.Index)
	switch loadBalancerType {
	case "Sticky_RR_v1":
		 runLoadBalancerV1(iface.Index)
	default:
		// runLoadBalancerV1(iface.Index)
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

func runLoadBalancerV1(ifaceIndex int) link.Link{
	// Load the eBPF program and maps into the kernel.
	objs := lb_sticky_rr_v1Objects{}
	if err := loadLb_sticky_rr_v1Objects(&objs, nil); err != nil {
		log.Fatalf("loading lb_sticky_rr_v1 objects: %v", err)
	}

	if err := objs.lb_sticky_rr_v1Variables.CurrentBackendIndex.Set(uint32(0)); err != nil {
		log.Fatalf("setting lb_v1Variables CurrentBackendIndex (Err: %v)", err)
	}

	// populate BPF map
	ipAddresses := [3]string{"10.0.1.2", "10.0.2.2", "10.0.3.2"}
	macAddresses := [3]string{
		"11:22:33:44:55:66",
		"77:99:99:AA:BB:CC",
		"DD:FF:12:23:34:56",
	}
	for i,address := range ipAddresses {
		ip := net.ParseIP(address)
		if ip == nil {
			log.Fatalf("invalid IP address: %s", address)
		}

		mac, err := net.ParseMAC(macAddresses[i])
		if err != nil {
			log.Fatalf("invalid MAC address: %s (%v)", macAddresses[i], err)
		}

		var backend BackendAddr

		backend.IP = binary.BigEndian.Uint32(ip.To4())

		// Detect and set family
		// if ip.To4() != nil {
		// 	backend.Family = uint8(unix.AF_INET)
		// 	copy(backend.IP[:4], ip.To4())
		// } else {
		// 	backend.Family = uint8(unix.AF_INET6)
		// 	copy(backend.IP[:16], ip.To16())
		// }

		// Copy MAC (net.HardwareAddr is already []byte)
		copy(backend.MAC[:], mac)

		// Finally, put into the BPF map
		if err := objs.lb_sticky_rr_v1Maps.Backends.Put(uint32(i), backend); err != nil {
			log.Fatalf("putting backend #%d failed: %v", i, err)
		}
	}
	
	// // Attach the program to Ingress TC.
	// l, err := link.AttachTCX(link.TCXOptions{
	// 	Interface: ifaceIndex,
	// 	Program:   objs.lb_sticky_rr_v1Programs.LoadBalancerRrV1,
	// 	Attach:    ebpf.AttachTCXIngress,
	// })
	// Attach the program at XDP .
	l, err := link.AttachXDP(link.XDPOptions{
		Interface: ifaceIndex,
		Program: objs.lb_sticky_rr_v1Programs.XdpLoadBalancerRr,
		},
	)

	if err != nil {
		log.Fatalf("could not attach XDP program: %s", err)
	}

	defer l.Close() 


	log.Println("attched XDP program on interface ", ifaceIndex)

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