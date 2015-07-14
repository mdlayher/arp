// Package arp implements an ARP client and server, as described in RFC 826.
package arp

//go:generate stringer -output=string.go -type=Operation

// Handler provides an interface which allows structs to act as ARP server
// handlers.  ServeARP implementations receive a copy of the incoming ARP
// request via the Request parameter, and allow outgoing communication via
// the ResponseSender.
//
// ServeARP implementations can choose to write a response packet using the
// ResponseSender interface, or choose to not write anything at all.
type Handler interface {
	ServeARP(ResponseSender, *Request)
}

// HandlerFunc is an adapter type which allows the use of normal functions as
// ARP handlers.  If f is a function with the appropriate signature,
// HandlerFunc(f) is a Handler struct that calls f.
type HandlerFunc func(ResponseSender, *Request)

// ServeARP calls f(w, r), allowing regular functions to implement Handler.
func (f HandlerFunc) ServeARP(w ResponseSender, r *Request) {
	f(w, r)
}

// ResponseSender provides an interface which allows a ARP handler to construct
// and send an ARP response packet.
type ResponseSender interface {
	Send(*Packet) (int, error)
}
