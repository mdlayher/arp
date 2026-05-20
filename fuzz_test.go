package arp

import "testing"

func FuzzPacketUnmarshalMarshal(f *testing.F) {
	// Seed: minimal valid ARP packet (6-byte ethernet, IPv4).
	f.Add([]byte{
		0, 1, // HardwareType
		8, 0, // ProtocolType
		6,    // HardwareAddrLength
		4,    // IPLength
		0, 1, // Operation
		0, 0, 0, 0, 0, 0, // sender hw
		192, 168, 1, 1, // sender IP
		0, 0, 0, 0, 0, 0, // target hw
		192, 168, 1, 2, // target IP
	})

	// Seed: HardwareAddrLength=128, IPLength=4. Exercises the uint8
	// overflow in (*Packet).MarshalBinary buffer allocation.
	f.Add(func() []byte {
		b := make([]byte, 8+128*2+4*2)
		b[0], b[1] = 0, 1 // HardwareType
		b[2], b[3] = 8, 0 // ProtocolType
		b[4] = 128        // HardwareAddrLength
		b[5] = 4          // IPLength
		b[6], b[7] = 0, 1 // Operation
		return b
	}())

	f.Fuzz(func(t *testing.T, b []byte) {
		p := new(Packet)
		if err := p.UnmarshalBinary(b); err != nil {
			return
		}
		if _, err := p.MarshalBinary(); err != nil {
			t.Fatal(err)
		}
	})
}
