package arp

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
)

func TestClientRequestInvalidSourceMAC(t *testing.T) {
	c := &Client{
		ifi: &net.Interface{},
	}

	_, got := c.Request(net.IPv4zero)
	if want := ErrInvalidMAC; want != got {
		t.Fatalf("unexpected error for invalid source MAC:\n- want: %v\n-  got: %v",
			want, got)
	}
}

func TestClientRequestIPv6Address(t *testing.T) {
	c := &Client{
		ifi: &net.Interface{
			HardwareAddr: net.HardwareAddr{0, 0, 0, 0, 0, 0},
		},
	}

	_, got := c.Request(net.IPv6loopback)
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
		ip: net.IPv4zero,
		p: &errWriteToPacketConn{
			err: errWriteTo,
		},
	}

	_, got := c.Request(net.IPv4zero)
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
		ip: net.IPv4zero,
		p: &errReadFromPacketConn{
			err: errReadFrom,
		},
	}

	_, got := c.Request(net.IPv4zero)
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
		ip: net.IPv4zero,
		p: &bufferReadFromPacketConn{
			b: bytes.NewBuffer([]byte{0}),
		},
	}

	_, got := c.Request(net.IPv4zero)
	if want := io.ErrUnexpectedEOF; want != got {
		t.Fatalf("unexpected error while reading ethernet frame:\n- want: %v\n-  got: %v",
			want, got)
	}
}

func TestClientRequestEthernetFrameWrongDestinationMAC(t *testing.T) {
	c := &Client{
		ifi: &net.Interface{
			HardwareAddr: net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0xde, 0xad},
		},
		ip: net.IPv4zero,
		p: &bufferReadFromPacketConn{
			b: bytes.NewBuffer(append([]byte{
				// Ethernet frame with wrong destination MAC address
				0, 0, 0, 0, 0, 0, // Wrong destination
				0, 0, 0, 0, 0, 0,
				0x00, 0x00,
			}, make([]byte, 46)...)),
		},
	}

	_, got := c.Request(net.IPv4zero)
	if want := io.EOF; want != got {
		t.Fatalf("unexpected error while reading ethernet frame with wrong destination MAC:\n- want: %v\n-  got: %v",
			want, got)
	}
}

func TestClientRequestEthernetFrameWrongEtherType(t *testing.T) {
	c := &Client{
		ifi: &net.Interface{
			HardwareAddr: net.HardwareAddr{0, 0, 0, 0, 0, 0},
		},
		ip: net.IPv4zero,
		p: &bufferReadFromPacketConn{
			b: bytes.NewBuffer(append([]byte{
				// Ethernet frame with non-ARP EtherType
				0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0,
				0x00, 0x00, // Wrong EtherType
			}, make([]byte, 46)...)),
		},
	}

	_, got := c.Request(net.IPv4zero)
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
		ip: net.IPv4zero,
		p: &bufferReadFromPacketConn{
			b: bytes.NewBuffer(append([]byte{
				// Ethernet frame
				0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0,
				0x08, 0x06,
				// ARP packet with misleading MAC address length
				0, 0,
				0, 0,
				255, 255, // Misleading MAC address length
			}, make([]byte, 40)...)),
		},
	}

	_, got := c.Request(net.IPv4zero)
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
		ip: net.IPv4zero,
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

	_, got := c.Request(net.IPv4zero)
	if want := io.EOF; want != got {
		t.Fatalf("unexpected error while reading ARP response with wrong operation type:\n- want: %v\n-  got: %v",
			want, got)
	}
}

func TestClientRequestARPResponseWrongTargetIP(t *testing.T) {
	c := &Client{
		ifi: &net.Interface{
			HardwareAddr: net.HardwareAddr{0, 0, 0, 0, 0, 0},
		},
		ip: net.IPv4(192, 168, 1, 1).To4(),
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
				0, 0, 0, 0,
				0, 0, 0, 0, 0, 0,
				192, 168, 1, 2, // Wrong IP address
			}, make([]byte, 46)...)),
		},
	}

	_, got := c.Request(net.IPv4zero)
	if want := io.EOF; want != got {
		t.Fatalf("unexpected error while reading ARP response with wrong target IP:\n- want: %v\n-  got: %v",
			want, got)
	}
}

func TestClientRequestARPResponseWrongTargetMAC(t *testing.T) {
	c := &Client{
		ifi: &net.Interface{
			HardwareAddr: net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0xde, 0xad},
		},
		ip: net.IPv4(192, 168, 1, 1).To4(),
		p: &bufferReadFromPacketConn{
			b: bytes.NewBuffer(append([]byte{
				// Ethernet frame
				0xde, 0xad, 0xbe, 0xef, 0xde, 0xad,
				0, 0, 0, 0, 0, 0,
				0x08, 0x06,
				// ARP Packet not bound for this MAC address
				0, 1,
				0x08, 0x06,
				6,
				4,
				0, 2,
				0, 0, 0, 0, 0, 0,
				0, 0, 0, 0,
				0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // Wrong MAC address
				192, 168, 1, 1,
			}, make([]byte, 46)...)),
		},
	}

	_, got := c.Request(net.IPv4zero)
	if want := io.EOF; want != got {
		t.Fatalf("unexpected error while reading ARP response with wrong target MAC:\n- want: %v\n-  got: %v",
			want, got)
	}
}

func TestClientRequestOK(t *testing.T) {
	c := &Client{
		ifi: &net.Interface{
			HardwareAddr: net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0xde, 0xad},
		},
		ip: net.IPv4(192, 168, 1, 1).To4(),
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
				0xde, 0xad, 0xbe, 0xef, 0xde, 0xad,
				192, 168, 1, 1,
			}, make([]byte, 40)...)),
		},
	}

	wantMAC := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	gotMAC, err := c.Request(net.IPv4zero)
	if err != nil {
		t.Fatal(err)
	}

	if want, got := wantMAC, gotMAC; !bytes.Equal(want, got) {
		t.Fatalf("unexpected MAC address for request:\n- want: %v\n-  got: %v",
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
