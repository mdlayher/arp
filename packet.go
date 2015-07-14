package arp

import (
	"encoding/binary"
	"errors"
	"io"
	"net"

	"github.com/mdlayher/ethernet"
)

var (
	// ErrInvalidMAC is returned when one or more invalid MAC addresses are
	// passed to NewPacket.
	ErrInvalidMAC = errors.New("invalid MAC address")

	// ErrInvalidIP is returned when one or more invalid IPv4 addresses are
	// passed to NewPacket.
	ErrInvalidIP = errors.New("invalid IPv4 address")
)

// An Operation is an ARP operation, such as request or reply.
type Operation uint16

// Operation constants which indicate an ARP request or reply.
const (
	OperationRequest Operation = 1
	OperationReply   Operation = 2
)

// A Packet is a raw ARP packet, as described in RFC 826.
type Packet struct {
	// HardwareType specifies an IANA-assigned hardware type, as described
	// in RFC 826.
	HardwareType uint16

	// ProtocolType specifies the internetwork protocol for which the ARP
	// request is intended.  Typically, this is the IPv4 EtherType.
	ProtocolType uint16

	// MACLength specifies the length of the sender and target MAC addresses
	// included in a Packet.
	MACLength uint8

	// IPLength specifies the length of the sender and target IPv4 addresses
	// included in a Packet.
	IPLength uint8

	// Operation specifies the ARP operation being performed, such as request
	// or reply.
	Operation Operation

	// SenderMAC specifies the MAC address of the sender of this Packet.
	SenderMAC net.HardwareAddr

	// SenderIP specifies the IPv4 address of the sender of this Packet.
	SenderIP net.IP

	// TargetMAC specifies the MAC address of the target of this Packet.
	TargetMAC net.HardwareAddr

	// TargetIP specifies the IPv4 address of the target of this Packet.
	TargetIP net.IP
}

// NewPacket creates a new Packet from an input Operation and MAC/IPv4 address
// values for both a sender and target.
//
// If either MAC address is less than 6 bytes in length, or there is a length
// mismatch between the two, ErrInvalidMAC is returned.
//
// If either IP address is not an IPv4 address, or there is a length mismatch
// between the two, ErrInvalidIP is returned.
func NewPacket(op Operation, srcMAC net.HardwareAddr, srcIP net.IP, dstMAC net.HardwareAddr, dstIP net.IP) (*Packet, error) {
	// Validate MAC addresses for minimum length, and matching length
	if len(srcMAC) < 6 {
		return nil, ErrInvalidMAC
	}
	if len(dstMAC) < 6 {
		return nil, ErrInvalidMAC
	}
	if len(srcMAC) != len(dstMAC) {
		return nil, ErrInvalidMAC
	}

	// Validate IP addresses to ensure they are IPv4 addresses, and
	// correct length
	srcIP = srcIP.To4()
	if srcIP == nil {
		return nil, ErrInvalidIP
	}
	dstIP = dstIP.To4()
	if dstIP == nil {
		return nil, ErrInvalidIP
	}

	return &Packet{
		// There is no Go-native way to detect hardware type of a network
		// interface, so default to 1 (ethernet 10Mb) for now
		HardwareType: 1,

		// Default to EtherType for IPv4
		ProtocolType: uint16(ethernet.EtherTypeIPv4),

		// Populate other fields using input data
		MACLength: uint8(len(srcMAC)),
		IPLength:  uint8(len(srcIP)),
		Operation: op,
		SenderMAC: srcMAC,
		SenderIP:  srcIP,
		TargetMAC: dstMAC,
		TargetIP:  dstIP,
	}, nil
}

// MarshalBinary allocates a byte slice containing the data from a Packet.
//
// MarshalBinary never returns an error.
func (p *Packet) MarshalBinary() ([]byte, error) {
	// 2 bytes: hardware type
	// 2 bytes: protocol type
	// 1 byte : hardware address length
	// 1 byte : protocol length
	// 2 bytes: operation
	// N bytes: source hardware address
	// 4 bytes: source protocol address
	// N bytes: target hardware address
	// 4 bytes: target protocol address
	b := make([]byte, 2+2+1+1+2+4+4+(p.MACLength*2))

	// Marshal fixed length data

	binary.BigEndian.PutUint16(b[0:2], p.HardwareType)
	binary.BigEndian.PutUint16(b[2:4], p.ProtocolType)

	b[4] = p.MACLength
	b[5] = p.IPLength

	binary.BigEndian.PutUint16(b[6:8], uint16(p.Operation))

	// Marshal variable length data at correct offset using lengths
	// defined in p

	n := 8
	hal := int(p.MACLength)
	pl := int(p.IPLength)

	copy(b[n:n+hal], p.SenderMAC)
	n += hal

	copy(b[n:n+pl], p.SenderIP)
	n += pl

	copy(b[n:n+hal], p.TargetMAC)
	n += hal

	copy(b[n:n+pl], p.TargetIP)

	return b, nil
}

// UnmarshalBinary unmarshals a raw byte slice into a Packet.
func (p *Packet) UnmarshalBinary(b []byte) error {
	// Must have enough room to retrieve MAC and IP lengths
	if len(b) < 8 {
		return io.ErrUnexpectedEOF
	}

	// Retrieve fixed length data

	p.HardwareType = binary.BigEndian.Uint16(b[0:2])
	p.ProtocolType = binary.BigEndian.Uint16(b[2:4])

	p.MACLength = b[4]
	p.IPLength = b[5]

	p.Operation = Operation(binary.BigEndian.Uint16(b[6:8]))

	// Unmarshal variable length data at correct offset using lengths
	// defined by ml and il
	n := 8
	ml := int(p.MACLength)
	il := int(p.IPLength)

	// Must have enough room to retrieve both MAC and IP addresses
	if len(b) < 8+(2*ml)+(2*il) {
		return io.ErrUnexpectedEOF
	}

	sha := make(net.HardwareAddr, ml)
	copy(sha, b[n:n+ml])
	p.SenderMAC = sha
	n += ml

	spa := make(net.IP, il)
	copy(spa, b[n:n+il])
	p.SenderIP = spa
	n += il

	tha := make(net.HardwareAddr, ml)
	copy(tha, b[n:n+ml])
	p.TargetMAC = tha
	n += ml

	tpa := make(net.IP, il)
	copy(tpa, b[n:n+il])
	p.TargetIP = tpa

	return nil
}
