package arp

import (
	"bytes"
	"errors"
	"net"
	"time"

	"github.com/mdlayher/ethernet"
	"github.com/mdlayher/raw"
)

var (
	// errNoIPv4Addr is returned when an interface does not have an IPv4
	// address.
	errNoIPv4Addr = errors.New("no IPv4 address available for interface")
)

// A Client is an ARP client, which can be used to send ARP requests to
// retrieve the hardware address of a machine using its IPv4 address.
type Client struct {
	ifi *net.Interface
	ip  net.IP
	p   net.PacketConn
}

// NewClient creates a new Client using the specified network interface.
// NewClient retrieves the IPv4 address of the interface and binds a raw socket
// to send and receive ARP packets.
func NewClient(ifi *net.Interface) (*Client, error) {
	// Open raw socket to send and receive ARP packets using ethernet frames
	// we build ourselves
	p, err := raw.ListenPacket(ifi, raw.ProtocolARP)
	if err != nil {
		return nil, err
	}

	// Check for usable IPv4 addresses for the Client
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil, err
	}

	return newClient(ifi, p, addrs)
}

// newClient is the internal, generic implementation of newClient.  It is used
// to allow an arbitrary net.PacketConn to be used in a Client, so testing
// is easier to accomplish.
func newClient(ifi *net.Interface, p net.PacketConn, addrs []net.Addr) (*Client, error) {
	ip, err := firstIPv4Addr(addrs)
	if err != nil {
		return nil, err
	}

	return &Client{
		ifi: ifi,
		ip:  ip,
		p:   p,
	}, nil
}

// Close closes the Client's raw socket and stops sending and receiving
// ARP packets.
func (c *Client) Close() error {
	return c.p.Close()
}

// Request performs an ARP request, attempting to retrieve the hardware address
// of a machine using its IPv4 address.
func (c *Client) Request(ip net.IP) (net.HardwareAddr, error) {
	// Create ARP packet for broadcast address to attempt to find the
	// hardware address of the input IP address
	arp, err := NewPacket(OperationRequest, c.ifi.HardwareAddr, c.ip, ethernet.Broadcast, ip)
	if err != nil {
		return nil, err
	}
	arpb, err := arp.MarshalBinary()
	if err != nil {
		return nil, err
	}

	// Create ethernet frame addressed to broadcast address to encapsulate the
	// ARP packet
	eth := &ethernet.Frame{
		Destination: ethernet.Broadcast,
		Source:      c.ifi.HardwareAddr,
		EtherType:   ethernet.EtherTypeARP,
		Payload:     arpb,
	}
	ethb, err := eth.MarshalBinary()
	if err != nil {
		return nil, err
	}

	// Write frame to ethernet broadcast address
	_, err = c.p.WriteTo(ethb, &raw.Addr{
		HardwareAddr: ethernet.Broadcast,
	})
	if err != nil {
		return nil, err
	}

	// Loop and wait for replies
	buf := make([]byte, 128)
	for {
		n, _, err := c.p.ReadFrom(buf)
		if err != nil {
			return nil, err
		}

		// Unmarshal ethernet frame and check:
		//   - Frame is for our hardware address
		//   - Frame has ARP EtherType
		if err := eth.UnmarshalBinary(buf[:n]); err != nil {
			return nil, err
		}
		if !bytes.Equal(eth.Destination, c.ifi.HardwareAddr) {
			continue
		}
		if eth.EtherType != ethernet.EtherTypeARP {
			continue
		}

		// Unmarshal ARP packet and check:
		//   - Packet is a reply, not a request
		//   - Packet is for our IP address
		//   - Packet is for our hardware address
		if err := arp.UnmarshalBinary(eth.Payload); err != nil {
			return nil, err
		}
		if arp.Operation != OperationReply {
			continue
		}
		if !bytes.Equal(arp.TargetIP, c.ip) {
			continue
		}
		if !bytes.Equal(arp.TargetHardwareAddr, c.ifi.HardwareAddr) {
			continue
		}

		return arp.SenderHardwareAddr, nil
	}
}

// Copyright (c) 2012 The Go Authors. All rights reserved.
// Source code in this file is based on src/net/interface_linux.go,
// from the Go standard library.  The Go license can be found here:
// https://golang.org/LICENSE.

// Documentation taken from net.PacketConn interface.  Thanks:
// http://golang.org/pkg/net/#PacketConn.

// SetDeadline sets the read and write deadlines associated with the
// connection.
func (c *Client) SetDeadline(t time.Time) error {
	return c.p.SetDeadline(t)
}

// SetReadDeadline sets the deadline for future raw socket read calls.
// If the deadline is reached, a raw socket read will fail with a timeout
// (see type net.Error) instead of blocking.
// A zero value for t means a raw socket read will not time out.
func (c *Client) SetReadDeadline(t time.Time) error {
	return c.p.SetReadDeadline(t)
}

// SetWriteDeadline sets the deadline for future raw socket write calls.
// If the deadline is reached, a raw socket write will fail with a timeout
// (see type net.Error) instead of blocking.
// A zero value for t means a raw socket write will not time out.
// Even if a write times out, it may return n > 0, indicating that
// some of the data was successfully written.
func (c *Client) SetWriteDeadline(t time.Time) error {
	return c.p.SetWriteDeadline(t)
}

// firstIPv4Addr attempts to retrieve the first detected IPv4 address from an
// input slice of network addresses.
func firstIPv4Addr(addrs []net.Addr) (net.IP, error) {
	for _, a := range addrs {
		if a.Network() != "ip+net" {
			continue
		}

		ip, _, err := net.ParseCIDR(a.String())
		if err != nil {
			return nil, err
		}

		// "If ip is not an IPv4 address, To4 returns nil."
		// Reference: http://golang.org/pkg/net/#IP.To4
		if ip4 := ip.To4(); ip4 != nil {
			return ip4, nil
		}
	}

	return nil, errNoIPv4Addr
}
