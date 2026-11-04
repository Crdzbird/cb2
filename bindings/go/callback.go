package cb2

/*
#include <stddef.h>
#include <stdint.h>
*/
import "C"

import (
	"runtime/cgo"
	"unsafe"
)

type callbacks struct {
	replay      func(string) bool
	proofReplay func(string) bool
	recovered   any
	handle      cgo.Handle
}

func newCallbacks(r *Rules) *callbacks {
	c := &callbacks{replay: r.Replay, proofReplay: r.ProofReplay}
	c.handle = cgo.NewHandle(c)
	return c
}

func (c *callbacks) release() {
	c.handle.Delete()
}

func (c *callbacks) user() C.uintptr_t {
	return C.uintptr_t(c.handle)
}

func flag(on bool) C.int {
	if on {
		return 1
	}
	return 0
}

func (c *callbacks) rethrow() {
	if c.recovered != nil {
		panic(c.recovered)
	}
}

func (c *callbacks) run(fn func(string) bool, jti *C.char, n C.size_t) (result C.int) {
	defer func() {
		if r := recover(); r != nil {
			c.recovered = r
			result = 0
		}
	}()
	if fn == nil || !fn(C.GoStringN(jti, C.int(n))) {
		return 0
	}
	return 1
}

//export cb2GoReplay
func cb2GoReplay(user unsafe.Pointer, jti *C.char, n C.size_t) C.int {
	c := cgo.Handle(uintptr(user)).Value().(*callbacks)
	return c.run(c.replay, jti, n)
}

//export cb2GoProofReplay
func cb2GoProofReplay(user unsafe.Pointer, jti *C.char, n C.size_t) C.int {
	c := cgo.Handle(uintptr(user)).Value().(*callbacks)
	return c.run(c.proofReplay, jti, n)
}
