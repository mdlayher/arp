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

	// SenderMAC specifies the MAC address of the sender of this Request.
	SenderMAC net.HardwareAddr

	// SenderIP specifies the IPv4 address of the sender of this Request.
	SenderIP net.IP

	// TargetMAC specifies the MAC address of the target of this Request.
	TargetMAC net.HardwareAddr

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
		Operation: p.Operation,
		SenderMAC: p.SenderMAC,
		SenderIP:  p.SenderIP,
		TargetMAC: p.TargetMAC,
		TargetIP:  p.TargetIP,
	}, nil
}
