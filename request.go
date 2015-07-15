package arp

import (
	"errors"
	"net"

	"github.com/mdlayher/ethernet"
)

var (
	// errInvalidARPPacket is returned when an ethernet frame does not
	// indicate that an ARP packet is contained in its payload.
	errInvalidARPPacket = errors.New("invalid ARP packet")
)

// A Request is a processed ARP request received by a server.  Its fields
// contain information regarding the request's operation, sender information,
// and target information.
type Request struct {
	// Operation specifies the ARP operation being performed, such as request
	// or reply.
	Operation Operation

	// SenderHardwareAddr specifies the hardware address of the sender of this
	// Request.
	SenderHardwareAddr net.HardwareAddr

	// SenderIP specifies the IPv4 address of the sender of this Request.
	SenderIP net.IP

	// TargetHardwareAddr specifies the hardware address of the target of this
	// Request.
	TargetHardwareAddr net.HardwareAddr

	// TargetIP specifies the IPv4 address of the target of this Request.
	TargetIP net.IP
}

// parseRequest unmarshals a raw ethernet frame and an ARP packet into a Request.
func parseRequest(buf []byte) (*Request, error) {
	f := new(ethernet.Frame)
	if err := f.UnmarshalBinary(buf); err != nil {
		return nil, err
	}

	// Ignore frames which do not have ARP EtherType
	if f.EtherType != ethernet.EtherTypeARP {
		return nil, errInvalidARPPacket
	}

	p := new(Packet)
	if err := p.UnmarshalBinary(f.Payload); err != nil {
		return nil, err
	}

	return &Request{
		Operation:          p.Operation,
		SenderHardwareAddr: p.SenderHardwareAddr,
		SenderIP:           p.SenderIP,
		TargetHardwareAddr: p.TargetHardwareAddr,
		TargetIP:           p.TargetIP,
	}, nil
}
