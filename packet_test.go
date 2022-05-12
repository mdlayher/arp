package arp

import (
	"bytes"
	"io"
	"net"
	"net/netip"
	"reflect"
	"testing"

	"github.com/mdlayher/ethernet"
)

func TestNewPacket(t *testing.T) {
	zeroHW := net.HardwareAddr{0, 0, 0, 0, 0, 0}

	iboip1 := net.HardwareAddr(bytes.Repeat([]byte{0}, 20))

	tests := []struct {
		desc  string
		op    Operation
		srcHW net.HardwareAddr
		srcIP netip.Addr
		dstHW net.HardwareAddr
		dstIP netip.Addr
		p     *Packet
		err   error
	}{
		{
			desc:  "short source hardware address",
			srcHW: net.HardwareAddr{0, 0, 0, 0, 0},
			err:   ErrInvalidHardwareAddr,
		},
		{
			desc:  "short destination hardware address",
			srcHW: zeroHW,
			dstHW: net.HardwareAddr{0, 0, 0, 0, 0},
			err:   ErrInvalidHardwareAddr,
		},
		{
			desc:  "hardware address length mismatch",
			srcHW: zeroHW,
			dstHW: net.HardwareAddr{0, 0, 0, 0, 0, 0, 0, 0},
			err:   ErrInvalidHardwareAddr,
		},
		{
			desc:  "IPv6 source IP address",
			srcHW: zeroHW,
			dstHW: zeroHW,
			srcIP: netip.IPv6Unspecified(),
			err:   ErrInvalidIP,
		},
		{
			desc:  "IPv6 destination IP address",
			srcHW: zeroHW,
			dstHW: zeroHW,
			srcIP: netip.IPv4Unspecified(),
			dstIP: netip.IPv6Unspecified(),
			err:   ErrInvalidIP,
		},
		{
			desc:  "Gratuitous ARP request, IPoIB hardware addresses",
			op:    OperationRequest,
			srcHW: iboip1,
			dstHW: ethernet.Broadcast,
			srcIP: netip.IPv4Unspecified(),
			dstIP: netip.IPv4Unspecified(),
			p: &Packet{
				HardwareType:       1,
				ProtocolType:       uint16(ethernet.EtherTypeIPv4),
				HardwareAddrLength: 20,
				IPLength:           4,
				Operation:          OperationRequest,
				SenderHardwareAddr: iboip1,
				SenderIP:           netip.IPv4Unspecified(),
				TargetHardwareAddr: ethernet.Broadcast,
				TargetIP:           netip.IPv4Unspecified(),
			},
		},
		{
			desc:  "OK",
			op:    OperationRequest,
			srcHW: zeroHW,
			dstHW: zeroHW,
			srcIP: netip.IPv4Unspecified(),
			dstIP: netip.IPv4Unspecified(),
			p: &Packet{
				HardwareType:       1,
				ProtocolType:       uint16(ethernet.EtherTypeIPv4),
				HardwareAddrLength: 6,
				IPLength:           4,
				Operation:          OperationRequest,
				SenderHardwareAddr: zeroHW,
				SenderIP:           netip.IPv4Unspecified(),
				TargetHardwareAddr: zeroHW,
				TargetIP:           netip.IPv4Unspecified(),
			},
		},
	}

	for i, tt := range tests {
		p, err := NewPacket(tt.op, tt.srcHW, tt.srcIP, tt.dstHW, tt.dstIP)
		if err != nil {
			if want, got := tt.err, err; want != got {
				t.Fatalf("[%02d] test %q, unexpected error: %v != %v",
					i, tt.desc, want, got)
			}

			continue
		}

		if want, got := tt.p, p; !reflect.DeepEqual(want, got) {
			t.Fatalf("[%02d] test %q, unexpected Packet:\n- want: %v\n-  got: %v",
				i, tt.desc, want, got)
		}
	}
}

func TestPacketMarshalBinary(t *testing.T) {
	zeroHW := net.HardwareAddr{0, 0, 0, 0, 0, 0}
	ip1 := netip.MustParseAddr("192.168.1.10")
	ip2 := netip.MustParseAddr("192.168.1.1")

	iboip1 := net.HardwareAddr(bytes.Repeat([]byte{0}, 20))
	iboip2 := net.HardwareAddr(bytes.Repeat([]byte{1}, 20))

	tests := []struct {
		desc string
		p    *Packet
		b    []byte
	}{
		{
			desc: "ARP request to ethernet broadcast, 6 byte hardware addresses",
			p: &Packet{
				HardwareType:       1,
				ProtocolType:       uint16(ethernet.EtherTypeIPv4),
				HardwareAddrLength: 6,
				IPLength:           4,
				Operation:          OperationRequest,
				SenderHardwareAddr: zeroHW,
				SenderIP:           ip1,
				TargetHardwareAddr: ethernet.Broadcast,
				TargetIP:           ip2,
			},
			b: []byte{
				0, 1,
				8, 0,
				6,
				4,
				0, 1,
				0, 0, 0, 0, 0, 0,
				192, 168, 1, 10,
				255, 255, 255, 255, 255, 255,
				192, 168, 1, 1,
			},
		},
		{
			desc: "ARP reply over infiniband, 20 byte hardware addresses",
			p: &Packet{
				HardwareType:       32,
				ProtocolType:       uint16(ethernet.EtherTypeIPv4),
				HardwareAddrLength: 20,
				IPLength:           4,
				Operation:          OperationReply,
				SenderHardwareAddr: iboip1,
				SenderIP:           ip1,
				TargetHardwareAddr: iboip2,
				TargetIP:           ip2,
			},
			b: []byte{
				0, 32,
				8, 0,
				20,
				4,
				0, 2,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				192, 168, 1, 10,
				1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
				1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
				192, 168, 1, 1,
			},
		},
	}

	for i, tt := range tests {
		b, err := tt.p.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}

		if want, got := tt.b, b; !bytes.Equal(want, got) {
			t.Fatalf("[%02d] test %q, unexpected Packet bytes:\n- want: %v\n-  got: %v",
				i, tt.desc, want, got)
		}
	}
}

func TestPacketUnmarshalBinary(t *testing.T) {
	zeroHW := net.HardwareAddr{0, 0, 0, 0, 0, 0}
	ip1 := netip.MustParseAddr("192.168.1.10")
	ip2 := netip.MustParseAddr("192.168.1.1")

	iboip1 := net.HardwareAddr(bytes.Repeat([]byte{0}, 20))
	iboip2 := net.HardwareAddr(bytes.Repeat([]byte{1}, 20))

	tests := []struct {
		desc string
		p    *Packet
		b    []byte
		err  error
	}{
		{
			desc: "short buffer",
			b:    bytes.Repeat([]byte{0}, 7),
			err:  io.ErrUnexpectedEOF,
		},
		{
			desc: "short buffer, too short for hardware addresses",
			b: []byte{
				0, 1,
				8, 0,
				255,
				4,
				0, 1,
			},
			err: io.ErrUnexpectedEOF,
		},
		{
			desc: "short buffer, too short for IP addresses",
			b: []byte{
				0, 1,
				8, 0,
				6,
				255,
				0, 1,
			},
			err: io.ErrUnexpectedEOF,
		},
		{
			desc: "ARP request to ethernet broadcast, 6 byte hardware addresses",
			b: []byte{
				0, 1,
				8, 0,
				6,
				4,
				0, 1,
				0, 0, 0, 0, 0, 0,
				192, 168, 1, 10,
				255, 255, 255, 255, 255, 255,
				192, 168, 1, 1,
			},
			p: &Packet{
				HardwareType:       1,
				ProtocolType:       uint16(ethernet.EtherTypeIPv4),
				HardwareAddrLength: 6,
				IPLength:           4,
				Operation:          OperationRequest,
				SenderHardwareAddr: zeroHW,
				SenderIP:           ip1,
				TargetHardwareAddr: ethernet.Broadcast,
				TargetIP:           ip2,
			},
		},
		{
			desc: "ARP reply over infiniband, 20 byte hardware addresses",
			b: []byte{
				0, 32,
				8, 0,
				20,
				4,
				0, 2,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				192, 168, 1, 10,
				1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
				1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
				192, 168, 1, 1,
			},
			p: &Packet{
				HardwareType:       32,
				ProtocolType:       uint16(ethernet.EtherTypeIPv4),
				HardwareAddrLength: 20,
				IPLength:           4,
				Operation:          OperationReply,
				SenderHardwareAddr: iboip1,
				SenderIP:           ip1,
				TargetHardwareAddr: iboip2,
				TargetIP:           ip2,
			},
		},
	}

	for i, tt := range tests {
		p := new(Packet)
		if err := p.UnmarshalBinary(tt.b); err != nil {
			if want, got := tt.err, err; want != got {
				t.Fatalf("[%02d] test %q, unexpected error: %v != %v",
					i, tt.desc, want, got)
			}

			continue
		}

		if want, got := tt.p, p; !reflect.DeepEqual(want, got) {
			t.Fatalf("[%02d] test %q, unexpected Packet bytes:\n- want: %v\n-  got: %v",
				i, tt.desc, want, got)
		}
	}
}

func Test_parsePacket(t *testing.T) {
	tests := []struct {
		desc string
		buf  []byte
		p    *Packet
		err  error
	}{
		{
			desc: "invalid ethernet frame",
			err:  io.ErrUnexpectedEOF,
		},
		{
			desc: "non-ARP EtherType",
			// Approximation of 14 byte ethernet frame header and
			// 42 byte blank payload (EtherType 0x0000)
			buf: make([]byte, 56),
			err: errInvalidARPPacket,
		},
		{
			desc: "invalid ARP packet",
			buf: append([]byte{
				// Ethernet frame
				0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0,
				0x08, 0x06,
				// ARP packet with misleading hardware address length
				0, 0,
				0, 0,
				255, 255, // Misleading hardware address length
			}, make([]byte, 40)...),
			err: io.ErrUnexpectedEOF,
		},
		{
			desc: "OK",
			buf: append([]byte{
				// Ethernet frame
				0xde, 0xad, 0xbe, 0xef, 0xde, 0xad,
				0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
				0x08, 0x06,
				// ARP Packet
				0, 1,
				0x08, 0x06,
				6,
				4,
				0, 2,
				0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
				192, 168, 1, 10,
				0xde, 0xad, 0xbe, 0xef, 0xde, 0xad,
				192, 168, 1, 1,
			}, make([]byte, 40)...),
			p: &Packet{
				HardwareType:       1,
				ProtocolType:       2054,
				HardwareAddrLength: 6,
				IPLength:           4,
				Operation:          OperationReply,
				SenderHardwareAddr: net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
				SenderIP:           netip.MustParseAddr("192.168.1.10"),
				TargetHardwareAddr: net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0xde, 0xad},
				TargetIP:           netip.MustParseAddr("192.168.1.1"),
			},
		},
	}

	for i, tt := range tests {
		p, _, err := parsePacket(tt.buf)
		if err != nil {
			if want, got := tt.err, err; want != got {
				t.Fatalf("[%02d] test %q, unexpected error: %v != %v",
					i, tt.desc, want, got)
			}

			continue
		}

		if want, got := tt.p, p; !reflect.DeepEqual(want, got) {
			t.Fatalf("[%02d] test %q, unexpected Packet:\n- want: %v\n-  got: %v",
				i, tt.desc, want, got)
		}
	}
}

// Benchmarks for Packet.MarshalBinary

func BenchmarkPacketMarshalBinary(b *testing.B) {
	p, err := NewPacket(
		OperationRequest,
		net.HardwareAddr{0xad, 0xbe, 0xef, 0xde, 0xad, 0xde},
		netip.MustParseAddr("192.168.1.10"),
		net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0xde, 0xad},
		netip.MustParseAddr("192.168.1.1"),
	)
	if err != nil {
		b.Fatal(err)
	}

	benchmarkPacketMarshalBinary(b, p)
}

func benchmarkPacketMarshalBinary(b *testing.B, p *Packet) {
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := p.MarshalBinary(); err != nil {
			b.Fatal(err)
		}
	}
}

// Benchmarks for Packet.UnmarshalBinary

func BenchmarkPacketUnmarshalBinary(b *testing.B) {
	p, err := NewPacket(
		OperationRequest,
		net.HardwareAddr{0xad, 0xbe, 0xef, 0xde, 0xad, 0xde},
		netip.MustParseAddr("192.168.1.10"),
		net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0xde, 0xad},
		netip.MustParseAddr("192.168.1.1"),
	)
	if err != nil {
		b.Fatal(err)
	}

	benchmarkPacketUnmarshalBinary(b, p)
}

func benchmarkPacketUnmarshalBinary(b *testing.B, p *Packet) {
	pb, err := p.MarshalBinary()
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if err := p.UnmarshalBinary(pb); err != nil {
			b.Fatal(err)
		}
	}
}
