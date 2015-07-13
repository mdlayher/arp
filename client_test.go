package arp

import (
	"bytes"
	"net"
	"reflect"
	"testing"
)

func Test_newClient(t *testing.T) {
	var tests = []struct {
		desc  string
		addrs []net.Addr
		c     *Client
		err   error
	}{
		{
			desc: "no network addresses",
			err:  errNoIPv4Addr,
		},
		{
			desc: "OK",
			addrs: []net.Addr{
				&net.IPNet{
					IP:   net.IPv4(192, 168, 1, 1),
					Mask: []byte{255, 255, 255, 0},
				},
			},
			c: &Client{
				ip: net.IPv4(192, 168, 1, 1).To4(),
			},
			err: errNoIPv4Addr,
		},
	}

	for i, tt := range tests {
		c, err := newClient(nil, nil, tt.addrs)
		if err != nil {
			if want, got := tt.err.Error(), err.Error(); want != got {
				t.Fatalf("[%02d] test %q, unexpected error: %v != %v",
					i, tt.desc, want, got)
			}

			continue
		}

		if want, got := tt.c, c; !reflect.DeepEqual(want, got) {
			t.Fatalf("[%02d] test %q, unexpected Client: %v != %v",
				i, tt.desc, want, got)
		}
	}
}

func Test_firstIPv4Addr(t *testing.T) {
	var tests = []struct {
		desc  string
		addrs []net.Addr
		ip    net.IP
		err   error
	}{
		{
			desc: "no network addresses",
			err:  errNoIPv4Addr,
		},
		{
			desc: "non-IP network",
			addrs: []net.Addr{
				&net.UnixAddr{
					Name: "foo.sock",
					Net:  "unix",
				},
			},
			err: errNoIPv4Addr,
		},
		{
			desc: "bad CIDR address",
			addrs: []net.Addr{
				&net.IPNet{
					IP: net.IPv4(192, 168, 1, 1),
				},
			},
			err: &net.ParseError{
				Type: "CIDR address",
				Text: "<nil>",
			},
		},
		{
			desc: "IPv6 address only",
			addrs: []net.Addr{
				&net.IPNet{
					IP: net.IPv6loopback,
					Mask: []byte{
						0xff, 0xff, 0xff, 0xff,
						0xff, 0xff, 0xff, 0xff,
						0, 0, 0, 0,
						0, 0, 0, 0,
					},
				},
			},
			err: errNoIPv4Addr,
		},
		{
			desc: "IPv4 address only",
			addrs: []net.Addr{
				&net.IPNet{
					IP:   net.IPv4(192, 168, 1, 1),
					Mask: []byte{255, 255, 255, 0},
				},
			},
			ip: net.IPv4(192, 168, 1, 1),
		},
		{
			desc: "IPv4 and IPv6 addresses",
			addrs: []net.Addr{
				&net.IPNet{
					IP: net.IPv6loopback,
					Mask: []byte{
						0xff, 0xff, 0xff, 0xff,
						0xff, 0xff, 0xff, 0xff,
						0, 0, 0, 0,
						0, 0, 0, 0,
					},
				},
				&net.IPNet{
					IP:   net.IPv4(192, 168, 1, 1),
					Mask: []byte{255, 255, 255, 0},
				},
			},
			ip: net.IPv4(192, 168, 1, 1),
		},
		{
			desc: "multiple IPv4 addresses",
			addrs: []net.Addr{
				&net.IPNet{
					IP:   net.IPv4(10, 0, 0, 1),
					Mask: []byte{255, 0, 0, 0},
				},
				&net.IPNet{
					IP:   net.IPv4(192, 168, 1, 1),
					Mask: []byte{255, 255, 255, 0},
				},
			},
			ip: net.IPv4(10, 0, 0, 1),
		},
	}

	for i, tt := range tests {
		ip, err := firstIPv4Addr(tt.addrs)
		if err != nil {
			if want, got := tt.err.Error(), err.Error(); want != got {
				t.Fatalf("[%02d] test %q, unexpected error: %v != %v",
					i, tt.desc, want, got)
			}

			continue
		}

		if want, got := tt.ip.To4(), ip.To4(); !bytes.Equal(want, got) {
			t.Fatalf("[%02d] test %q, unexpected IPv4 address: %v != %v",
				i, tt.desc, want, got)
		}
	}
}
