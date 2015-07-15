package main

import (
	"bytes"
	"flag"
	"log"
	"net"

	"github.com/mdlayher/arp"
	"github.com/mdlayher/ethernet"
)

var (
	// ifaceFlag is used to set a network interface for ARP traffic
	ifaceFlag = flag.String("i", "eth0", "network interface to use for ARP traffic")

	// ipFlag is used to set an IPv4 address to proxy ARP on behalf of
	ipFlag = flag.String("ip", "", "IP address for device to proxy ARP on behalf of")
)

func main() {
	flag.Parse()

	// Ensure valid interface and IPv4 address
	ifi, err := net.InterfaceByName(*ifaceFlag)
	if err != nil {
		log.Fatal(err)
	}
	ip := net.ParseIP(*ipFlag).To4()
	if ip == nil {
		log.Fatalf("invalid IPv4 address: %q", *ipFlag)
	}

	// Handle ARP requests bound for designated IPv4 address, using proxy ARP
	// to indicate that the address belongs to this machine
	arp.HandleFunc(arp.OperationRequest, func(w arp.ResponseSender, r *arp.Request) {
		// Ignore ARP requests which are not broadcast or bound directly for
		// this machine
		if !bytes.Equal(r.TargetMAC, ethernet.Broadcast) && !bytes.Equal(r.TargetMAC, ifi.HardwareAddr) {
			return
		}

		log.Printf("request: who-has %s?  tell %s (%s)", r.TargetIP, r.SenderIP, r.SenderMAC)

		// Ignore ARP requests which do not indicate the target IP
		if !bytes.Equal(r.TargetIP, ip) {
			return
		}

		// Send reply indicating that this machine has the requested
		// IP address
		p, err := arp.NewPacket(
			arp.OperationReply,
			ifi.HardwareAddr,
			ip,
			r.SenderMAC,
			r.SenderIP,
		)
		if err != nil {
			log.Fatal(err)
		}

		log.Printf("  reply: %s is-at %s", ip, ifi.HardwareAddr)
		if _, err := w.Send(p); err != nil {
			log.Fatal(err)
		}
	})

	if err := arp.ListenAndServe(*ifaceFlag, nil); err != nil {
		log.Fatal(err)
	}
}
