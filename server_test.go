package arp

import (
	"bytes"
	"io"
	"log"
	"net"
	"testing"

	"github.com/mdlayher/ethernet"
	"github.com/mdlayher/raw"
)

func TestServeIgnoreInvalidEthernetFrame(t *testing.T) {
	// Send a request with invalid ethernet frame, expect no response,
	// use no handler
	p, err := testServe([]byte{0}, false, nil)
	if err != nil {
		t.Fatal(err)
	}

	if l := p.wb.Len(); l > 0 {
		t.Fatalf("should have no reply, but got %d bytes", l)
	}
}

func TestServeIgnoreWrongEtherType(t *testing.T) {
	// Approximation of 14 byte ethernet frame header and
	// 42 byte blank payload (EtherType 0x0000).
	// Expect no response, use no handler
	p, err := testServe(make([]byte, 56), false, nil)
	if err != nil {
		t.Fatal(err)
	}

	if l := p.wb.Len(); l > 0 {
		t.Fatalf("should have no reply, but got %d bytes", l)
	}
}

func TestServeNoResponse(t *testing.T) {
	// Valid ARP request, but handler will not send response
	b := append([]byte{
		// Ethernet frame
		0xde, 0xad, 0xbe, 0xef, 0xde, 0xad,
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		0x08, 0x06,
		// ARP Packet
		0, 1,
		0x08, 0x06,
		6,
		4,
		0, 1,
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		192, 168, 1, 10,
		0xde, 0xad, 0xbe, 0xef, 0xde, 0xad,
		192, 168, 1, 1,
	}, make([]byte, 40)...)

	// Send request, expect no response, send no response
	p, err := testServe(b, false, func(w ResponseSender, r *Request) {
		// Ensure proper processing of packet
		if want, got := OperationRequest, r.Operation; want != got {
			t.Fatalf("unexpected request operation: %v != %v", want, got)
		}

		if want, got := (net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}), r.SenderMAC; !bytes.Equal(want, got) {
			t.Fatalf("unexpected request sender MAC:\n- want: %v\n-  got: %v", want, got)
		}
		if want, got := (net.IP{192, 168, 1, 10}), r.SenderIP; !bytes.Equal(want, got) {
			t.Fatalf("unexpected request sender IP:\n- want: %v\n-  got: %v", want, got)
		}

		if want, got := (net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0xde, 0xad}), r.TargetMAC; !bytes.Equal(want, got) {
			t.Fatalf("unexpected request target MAC:\n- want: %v\n-  got: %v", want, got)
		}
		if want, got := (net.IP{192, 168, 1, 1}), r.TargetIP; !bytes.Equal(want, got) {
			t.Fatalf("unexpected request target IP:\n- want: %v\n-  got: %v", want, got)
		}
	})
	if err != nil {
		t.Fatal(err)
	}

	if l := p.wb.Len(); l > 0 {
		t.Fatalf("should have no reply, but got %d bytes", l)
	}
}

func TestServeOK(t *testing.T) {
	b := append([]byte{
		// Ethernet frame
		0xde, 0xad, 0xbe, 0xef, 0xde, 0xad,
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		0x08, 0x06,
		// ARP Packet
		0, 1,
		0x08, 0x06,
		6,
		4,
		0, 1,
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		192, 168, 1, 10,
		0xde, 0xad, 0xbe, 0xef, 0xde, 0xad,
		192, 168, 1, 1,
	}, make([]byte, 40)...)

	// Values to be sent in ARP reply and checked later
	wantsMAC := net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0xde, 0xad}
	wantsIP := net.IP{192, 168, 1, 1}

	wanttMAC := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	wanttIP := net.IP{192, 168, 1, 10}

	// Count bytes sent
	var n int
	p, err := testServe(b, true, func(w ResponseSender, r *Request) {
		// Build an ARP reply for request
		pkt, err := NewPacket(
			OperationReply,
			r.TargetMAC,
			r.TargetIP,
			r.SenderMAC,
			r.SenderIP,
		)
		if err != nil {
			t.Fatal(err)
		}

		n, err = w.Send(pkt)
		if err != nil {
			t.Fatal(err)
		}
		return
	})
	if err != nil {
		t.Fatal(err)
	}

	if want, got := n, p.wb.Len(); want != got {
		t.Fatalf("unexpected response length: %v != %v", want, got)
	}

	// Unmarshal ethernet frame and verify fields
	f := new(ethernet.Frame)
	if err := f.UnmarshalBinary(p.wb.Bytes()); err != nil {
		log.Println(len(p.wb.Bytes()))
		t.Fatal(err)
	}

	if want, got := wanttMAC, f.DestinationMAC; !bytes.Equal(want, got) {
		t.Fatalf("unexpected ethernet frame destination:\n- want: %v\n-  got: %v",
			want, got)
	}
	if want, got := wantsMAC, f.SourceMAC; !bytes.Equal(want, got) {
		t.Fatalf("unexpected ethernet frame source:\n- want: %v\n-  got: %v",
			want, got)
	}
	if want, got := ethernet.EtherTypeARP, f.EtherType; want != got {
		t.Fatalf("unexpected ethernet frame EtherType: %v != %v", want, got)
	}

	// Unmarshal ARP packet and verify fields
	pkt := new(Packet)
	if err := pkt.UnmarshalBinary(f.Payload); err != nil {
		t.Fatal(err)
	}

	// Hardware type is hardcoded
	if want, got := uint16(1), pkt.HardwareType; want != got {
		t.Fatalf("unexpected ARP packet hardware type: %v != %v", want, got)
	}
	// Protocol type is hardcoded
	if want, got := uint16(ethernet.EtherTypeIPv4), pkt.ProtocolType; want != got {
		t.Fatalf("unexpected ARP packet protocol type: %v != %v", want, got)
	}

	if want, got := uint8(len(wantsMAC)), pkt.MACLength; want != got {
		t.Fatalf("unexpected ARP packet MAC length: %v != %v", want, got)
	}
	if want, got := uint8(len(wantsIP)), pkt.IPLength; want != got {
		t.Fatalf("unexpected ARP packet IP length: %v != %v", want, got)
	}

	if want, got := OperationReply, pkt.Operation; want != got {
		t.Fatalf("unexpected ARP packet operation: %v != %v", want, got)
	}

	if want, got := wantsMAC, pkt.SenderMAC; !bytes.Equal(want, got) {
		t.Fatalf("unexpected ARP packet sender MAC:\n- want: %v\n-  got: %v",
			want, got)
	}
	if want, got := wantsIP, pkt.SenderIP; !bytes.Equal(want, got) {
		t.Fatalf("unexpected ARP packet sender IP:\n- want: %v\n-  got: %v",
			want, got)
	}
	if want, got := wanttMAC, pkt.TargetMAC; !bytes.Equal(want, got) {
		t.Fatalf("unexpected ARP packet target MAC:\n- want: %v\n-  got: %v",
			want, got)
	}
	if want, got := wanttIP, pkt.TargetIP; !bytes.Equal(want, got) {
		t.Fatalf("unexpected ARP packet target IP:\n- want: %v\n-  got: %v",
			want, got)
	}
}

func testServe(req []byte, expectReply bool, fn func(w ResponseSender, r *Request)) (*bufferPacketConn, error) {
	p := &bufferPacketConn{
		rb:     bytes.NewBuffer(req),
		raddr:  &raw.Addr{},
		rdoneC: make(chan struct{}),

		wb:     bytes.NewBuffer(nil),
		wdoneC: make(chan struct{}),
	}

	s := &Server{
		Handler: HandlerFunc(fn),
	}

	// If no reply is expected, this channel will never be closed,
	// and should be closed immediately
	if !expectReply {
		close(p.wdoneC)
	}

	// Handle request
	err := s.Serve(p)

	// Wait for read and write to complete
	<-p.rdoneC
	<-p.wdoneC

	return p, err
}

// bufferPacketConn is a net.PacketConn which reads and writes using
// buffers.
type bufferPacketConn struct {
	rb     *bytes.Buffer
	raddr  net.Addr
	rdoneC chan struct{}

	done bool

	wb     *bytes.Buffer
	waddr  net.Addr
	wdoneC chan struct{}

	noopPacketConn
}

func (p *bufferPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	if p.done {
		return 0, nil, io.EOF
	}

	n, err := p.rb.Read(b)
	close(p.rdoneC)
	p.done = true
	return n, p.raddr, err
}

func (p *bufferPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	p.waddr = addr
	n, err := p.wb.Write(b)
	close(p.wdoneC)
	return n, err
}
