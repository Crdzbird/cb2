package cb2

/*
#include "cb2_c.h"
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"runtime"
)

// ClaimTableDigestBytes is the length in bytes, 32, of a claim table's
// digest.
const ClaimTableDigestBytes = C.CB2_CLAIM_TABLE_DIGEST_BYTES

// ClaimTable is the claim table of the compact tokens (docs/PROTOCOL.md
// section 15.5): an ordered list of entries, typically the issuer's name
// and its audiences, that the issuer and its verifiers configure alike.
// Under a table an iss or aud equal to an entry travels as its index,
// and the table's digest is bound into the token, so a token opens only
// under the same table.
//
// A ClaimTable is immutable and safe for concurrent use by multiple
// goroutines. Close it when done; a finalizer releases the C handle of
// a table that becomes unreachable without Close.
type ClaimTable struct {
	h handle[*C.cb2_claim_table]
}

// NewClaimTable builds a table from 1 to 256 distinct, non-empty
// entries without control characters; anything else is refused with
// ErrArgument. The order of the entries is part of the table.
func NewClaimTable(entries []string) (*ClaimTable, error) {
	j, err := json.Marshal(entries)
	if err != nil {
		return nil, fmt.Errorf("cb2: encode claim table: %w", err)
	}
	var p *C.cb2_claim_table
	if err := check(C.cb2_claim_table_from_json(charPtr(j), C.size_t(len(j)), &p)); err != nil {
		return nil, err
	}
	t := &ClaimTable{}
	t.h.init(p, func(p *C.cb2_claim_table) { C.cb2_claim_table_free(p) })
	runtime.SetFinalizer(t, (*ClaimTable).Close)
	return t, nil
}

// Close releases the table. Calls already in flight finish first; later
// calls fail with ErrClosed. Close is idempotent.
func (t *ClaimTable) Close() {
	if t == nil {
		return
	}
	runtime.SetFinalizer(t, nil)
	t.h.close()
}

// Digest returns the table's digest, which two parties can compare to
// check that they hold the same table. A nil or closed table gives
// ErrClosed.
func (t *ClaimTable) Digest() ([ClaimTableDigestBytes]byte, error) {
	var d [ClaimTableDigestBytes]byte
	if t == nil {
		return d, ErrClosed
	}
	p := t.h.acquire()
	defer t.h.release()
	if p == nil {
		return d, ErrClosed
	}
	var out *C.uint8_t
	if err := check(C.cb2_claim_table_digest(p, &out)); err != nil {
		return d, err
	}
	b := takeBytes(out, ClaimTableDigestBytes)
	copy(d[:], b)
	return d, nil
}

func (t *ClaimTable) acquire() (*C.cb2_claim_table, error) {
	if t == nil {
		return nil, nil
	}
	p := t.h.acquire()
	if p == nil {
		t.h.release()
		return nil, ErrClosed
	}
	return p, nil
}

func (t *ClaimTable) release() {
	if t != nil {
		t.h.release()
	}
}
