//go:build !cb2_pkgconfig

package cb2

/*
#cgo CFLAGS: -I${SRCDIR}/../c/include
#cgo LDFLAGS: -L${SRCDIR}/../../build/bindings/c -lcb2_c -Wl,-rpath,${SRCDIR}/../../build/bindings/c
*/
import "C"
