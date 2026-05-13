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
