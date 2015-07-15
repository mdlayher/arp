package arp

import (
	"sync"
)

// DefaultServeMux is the default ServeMux used by Serve.  When the Handle and
// HandleFunc functions are called, handlers are applied to DefaultServeMux.
var DefaultServeMux = NewServeMux()

// ServeMux is a ARP request multiplexer, which implements Handler.  ServeMux
// matches handlers based on their Operation, enabling different handlers
// to be used for different types of ARP operations.  ServeMux can be helpful
// for structuring your application, but may not be needed for very simple
// ARP servers.
type ServeMux struct {
	mu sync.RWMutex
	m  map[Operation]Handler
}

// NewServeMux creates a new ServeMux which is ready to accept Handlers.
func NewServeMux() *ServeMux {
	return &ServeMux{
		m: make(map[Operation]Handler),
	}
}

// ServeARP implements Handler for ServeMux, and serves an ARP request using
// the appropriate handler for an input Request's Operation.  If the
// Operation does not match a valid Handler, ServeARP does not invoke any
// handlers, ignoring a client's request.
func (mux *ServeMux) ServeARP(w ResponseSender, r *Request) {
	mux.mu.RLock()
	defer mux.mu.RUnlock()
	h, ok := mux.m[r.Operation]
	if !ok {
		return
	}

	h.ServeARP(w, r)
}

// Handle registers a Operation and Handler with a ServeMux, so that
// future requests with that Operation will invoke the Handler.
func (mux *ServeMux) Handle(op Operation, handler Handler) {
	mux.mu.Lock()
	mux.m[op] = handler
	mux.mu.Unlock()
}

// Handle registers a Operation and Handler with the DefaultServeMux,
// so that future requests with that Operation will invoke the Handler.
func Handle(op Operation, handler Handler) {
	DefaultServeMux.Handle(op, handler)
}

// HandleFunc registers a Operation and function as a HandlerFunc with a
// ServeMux, so that future requests with that Operation will invoke the
// HandlerFunc.
func (mux *ServeMux) HandleFunc(op Operation, handler func(ResponseSender, *Request)) {
	mux.Handle(op, HandlerFunc(handler))
}

// HandleFunc registers a Operation and function as a HandlerFunc with the
// DefaultServeMux, so that future requests with that Operation will invoke
// the HandlerFunc.
func HandleFunc(op Operation, handler func(ResponseSender, *Request)) {
	DefaultServeMux.HandleFunc(op, handler)
}
