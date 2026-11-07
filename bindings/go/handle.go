package cb2

import "sync"

// handle guards one C key handle. Calls that read the key hold a use for
// the length of the C call and never block one another; Close marks the
// handle closed and the last use releases the C handle; a key id change
// waits until no use is in flight and keeps new uses out while it runs.
// No lock is held while a key is in use, so holding uses of several
// keys at once cannot deadlock. The zero value is a closed handle.
type handle[P comparable] struct {
	mu      sync.Mutex
	idle    sync.Cond
	p       P
	free    func(P)
	users   int
	writing bool
	closed  bool
}

func (h *handle[P]) init(p P, free func(P)) {
	h.idle.L = &h.mu
	h.p = p
	h.free = free
}

func (h *handle[P]) acquire() P {
	h.mu.Lock()
	defer h.mu.Unlock()
	for h.writing {
		h.idle.Wait()
	}
	h.users++
	if h.closed {
		var none P
		return none
	}
	return h.p
}

func (h *handle[P]) release() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.users--
	h.settle()
}

func (h *handle[P]) close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.closed = true
	h.settle()
}

func (h *handle[P]) mutate(fn func(P)) bool {
	h.mu.Lock()
	var none P
	for h.p != none && !h.closed && (h.writing || h.users > 0) {
		h.idle.Wait()
	}
	if h.p == none || h.closed {
		h.mu.Unlock()
		return false
	}
	h.writing = true
	p := h.p
	h.mu.Unlock()
	defer h.finishWrite()
	fn(p)
	return true
}

func (h *handle[P]) finishWrite() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.writing = false
	h.settle()
}

func (h *handle[P]) settle() {
	if h.users == 0 {
		h.idle.Broadcast()
	}
	var none P
	if h.closed && h.users == 0 && !h.writing && h.p != none {
		h.free(h.p)
		h.p = none
	}
}
