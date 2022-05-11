package arp

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
)

func ipv6loopback() netip.Addr {
	l := net.IPv6loopback
	a, ok := netip.AddrFromSlice(l)
	if !ok {
		panic("invalid loopback address")
	}
	return a
}

func TestClientRequestNoIPv4Address(t *testing.T) {
	c := &Client{}

	_, got := c.Resolve(netip.Addr{})
	if want := errNoIPv4Addr; want != got {
		t.Fatalf("unexpected error for no IPv4 address:\n- want: %v\n-  got: %v",
			want, got)
	}
}

func TestClientRequestInvalidSourceHardwareAddr(t *testing.T) {
	c := &Client{
		ifi: &net.Interface{},
		ip:  netip.IPv4Unspecified(),
	}

	_, got := c.Resolve(netip.IPv4Unspecified())
	if want := ErrInvalidHardwareAddr; want != got {
		t.Fatalf("unexpected error for invalid source hardware address:\n- want: %v\n-  got: %v",
			want, got)
	}
}

func TestClientRequestIPv6Address(t *testing.T) {
	c := &Client{
		ifi: &net.Interface{
			HardwareAddr: net.HardwareAddr{0, 0, 0, 0, 0, 0},
		},
		ip: netip.IPv4Unspecified(),
	}

	_, got := c.Resolve(ipv6loopback())
	if want := ErrInvalidIP; want != got {
		t.Fatalf("unexpected error for IPv6 address:\n- want: %v\n-  got: %v",
			want, got)
	}
}

func TestClientRequestErrWriteTo(t *testing.T) {
	errWriteTo := errors.New("test error")

	c := &Client{
		ifi: &net.Interface{
			HardwareAddr: net.HardwareAddr{0, 0, 0, 0, 0, 0},
		},
		ip: netip.IPv4Unspecified(),
		p: &errWriteToPacketConn{
			err: errWriteTo,
		},
	}

	_, got := c.Resolve(netip.IPv4Unspecified())
	if want := errWriteTo; want != got {
		t.Fatalf("unexpected error during WriteTo:\n- want: %v\n-  got: %v",
			want, got)
	}
}

func TestClientRequestErrReadFrom(t *testing.T) {
	errReadFrom := errors.New("test error")

	c := &Client{
		ifi: &net.Interface{
			HardwareAddr: net.HardwareAddr{0, 0, 0, 0, 0, 0},
		},
		ip: netip.IPv4Unspecified(),
		p: &errReadFromPacketConn{
			err: errReadFrom,
		},
	}

	_, got := c.Resolve(netip.IPv4Unspecified())
	if want := errReadFrom; want != got {
		t.Fatalf("unexpected error during ReadFrom:\n- want: %v\n-  got: %v",
			want, got)
	}
}

func TestClientRequestEthernetFrameUnexpectedEOF(t *testing.T) {
	c := &Client{
		ifi: &net.Interface{
			HardwareAddr: net.HardwareAddr{0, 0, 0, 0, 0, 0},
		},
		ip: netip.IPv4Unspecified(),
		p: &bufferReadFromPacketConn{
			b: bytes.NewBuffer([]byte{0}),
		},
	}

	_, got := c.Resolve(netip.IPv4Unspecified())
	if want := io.ErrUnexpectedEOF; want != got {
		t.Fatalf("unexpected error while reading ethernet frame:\n- want: %v\n-  got: %v",
			want, got)
	}
}

func TestClientRequestEthernetFrameWrongDestinationHardwareAddr(t *testing.T) {
	c := &Client{
		ifi: &net.Interface{
			HardwareAddr: net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0xde, 0xad},
		},
		ip: netip.IPv4Unspecified(),
		p: &bufferReadFromPacketConn{
			b: bytes.NewBuffer(append([]byte{
				// Ethernet frame with wrong destination hardware address
				0, 0, 0, 0, 0, 0, // Wrong destination
				0, 0, 0, 0, 0, 0,
				0x00, 0x00,
			}, make([]byte, 46)...)),
		},
	}

	_, got := c.Resolve(netip.IPv4Unspecified())
	if want := io.EOF; want != got {
		t.Fatalf("unexpected error while reading ethernet frame with wrong destination hardware address:\n- want: %v\n-  got: %v",
			want, got)
	}
}

func TestClientRequestEthernetFrameWrongEtherType(t *testing.T) {
	c := &Client{
		ifi: &net.Interface{
			HardwareAddr: net.HardwareAddr{0, 0, 0, 0, 0, 0},
		},
		ip: netip.IPv4Unspecified(),
		p: &bufferReadFromPacketConn{
			b: bytes.NewBuffer(append([]byte{
				// Ethernet frame with non-ARP EtherType
				0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0,
				0x00, 0x00, // Wrong EtherType
			}, make([]byte, 46)...)),
		},
	}

	_, got := c.Resolve(netip.IPv4Unspecified())
	if want := io.EOF; want != got {
		t.Fatalf("unexpected error while reading ethernet frame with wrong EtherType:\n- want: %v\n-  got: %v",
			want, got)
	}
}

func TestClientRequestARPPacketUnexpectedEOF(t *testing.T) {
	c := &Client{
		ifi: &net.Interface{
			HardwareAddr: net.HardwareAddr{0, 0, 0, 0, 0, 0},
		},
		ip: netip.IPv4Unspecified(),
		p: &bufferReadFromPacketConn{
			b: bytes.NewBuffer(append([]byte{
				// Ethernet frame
				0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0,
				0x08, 0x06,
				// ARP packet with misleading hardware address length
				0, 0,
				0, 0,
				255, 255, // Misleading hardware address length
			}, make([]byte, 40)...)),
		},
	}

	_, got := c.Resolve(netip.IPv4Unspecified())
	if want := io.ErrUnexpectedEOF; want != got {
		t.Fatalf("unexpected error while reading ARP packet:\n- want: %v\n-  got: %v",
			want, got)
	}
}

func TestClientRequestARPRequestInsteadOfResponse(t *testing.T) {
	c := &Client{
		ifi: &net.Interface{
			HardwareAddr: net.HardwareAddr{0, 0, 0, 0, 0, 0},
		},
		ip: netip.IPv4Unspecified(),
		p: &bufferReadFromPacketConn{
			b: bytes.NewBuffer(append([]byte{
				// Ethernet frame
				0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0,
				0x08, 0x06,
				// ARP request, not response
				0, 1,
				0x08, 0x06,
				6,
				4,
				0, 1, // Request, not Response
				0, 0, 0, 0, 0, 0,
				0, 0, 0, 0,
				0, 0, 0, 0, 0, 0,
				0, 0, 0, 0,
			}, make([]byte, 46)...)),
		},
	}

	_, got := c.Resolve(netip.IPv4Unspecified())
	if want := io.EOF; want != got {
		t.Fatalf("unexpected error while reading ARP response with wrong operation type:\n- want: %v\n-  got: %v",
			want, got)
	}
}

func TestClientRequestARPResponseWrongSenderIP(t *testing.T) {
	c := &Client{
		ifi: &net.Interface{
			HardwareAddr: net.HardwareAddr{0, 0, 0, 0, 0, 0},
		},
		ip: netip.AddrFrom4([4]byte{192, 168, 1, 1}),
		p: &bufferReadFromPacketConn{
			b: bytes.NewBuffer(append([]byte{
				// Ethernet frame
				0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0,
				0x08, 0x06,
				// ARP Packet not bound for this IP address
				0, 1,
				0x08, 0x06,
				6,
				4,
				0, 2,
				0, 0, 0, 0, 0, 0,
				192, 168, 1, 10, // Wrong IP address
				0, 0, 0, 0, 0, 0,
				192, 168, 1, 1,
			}, make([]byte, 46)...)),
		},
	}

	_, got := c.Resolve(netip.IPv4Unspecified())
	if want := io.EOF; want != got {
		t.Fatalf("unexpected error while reading ARP response with wrong sender IP:\n- want: %v\n-  got: %v",
			want, got)
	}
}

func TestClientRequestOK(t *testing.T) {
	c := &Client{
		ifi: &net.Interface{
			HardwareAddr: net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0xde, 0xad},
		},
		ip: netip.AddrFrom4([4]byte{192, 168, 1, 1}),
		p: &bufferReadFromPacketConn{
			b: bytes.NewBuffer(append([]byte{
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
				0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, // mac needn't match ours
				192, 168, 1, 2, // ip needn't match ours
			}, make([]byte, 40)...)),
		},
	}

	wantHW := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	gotHW, err := c.Resolve(netip.AddrFrom4([4]byte{192, 168, 1, 10}))
	if err != nil {
		t.Fatal(err)
	}

	if want, got := wantHW, gotHW; !bytes.Equal(want, got) {
		t.Fatalf("unexpected hardware address for request:\n- want: %v\n-  got: %v",
			want, got)
	}
}

// bufferReadFromPacketConn is a net.PacketConn which copies bytes from its
// embedded buffer into b when when its ReadFrom method is called.
type bufferReadFromPacketConn struct {
	b *bytes.Buffer

	noopPacketConn
}

func (p *bufferReadFromPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := p.b.Read(b)
	return n, nil, err
}

// errWriteToPacketConn is a net.PacketConn which always returns its embedded
// error when its WriteTo method is called.
type errWriteToPacketConn struct {
	err error

	noopPacketConn
}

func (p *errWriteToPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) { return 0, p.err }

// errReadFromPacketConn is a net.PacketConn which always returns its embedded
// error when its ReadFrom method is called.
type errReadFromPacketConn struct {
	err error

	noopPacketConn
}

func (p *errReadFromPacketConn) ReadFrom(b []byte) (int, net.Addr, error) { return 0, nil, p.err }
