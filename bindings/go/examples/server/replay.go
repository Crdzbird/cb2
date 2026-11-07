package main

import (
	"sync"
	"time"
)

// replayStore remembers the ids of holder proofs already accepted, each
// for window after it was first seen, which covers the proof lifetime
// the verifier allows. It is bounded: when full it refuses new ids, so
// the check fails closed instead of growing without limit.
type replayStore struct {
	mu        sync.Mutex
	seen      map[string]time.Time
	window    time.Duration
	limit     int
	lastPrune time.Time
	now       func() time.Time
}

func newReplayStore(window time.Duration, limit int, now func() time.Time) *replayStore {
	return &replayStore{
		seen:   make(map[string]time.Time),
		window: window,
		limit:  limit,
		now:    now,
	}
}

// firstUse records jti and reports whether it had not been seen within
// the window. It is the ProofReplay callback of the rules.
func (s *replayStore) firstUse(jti string) bool {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prune(now)
	if until, ok := s.seen[jti]; ok && now.Before(until) {
		return false
	}
	if len(s.seen) >= s.limit {
		return false
	}
	s.seen[jti] = now.Add(s.window)
	return true
}

func (s *replayStore) prune(now time.Time) {
	if now.Sub(s.lastPrune) < s.window/4 {
		return
	}
	s.lastPrune = now
	for id, until := range s.seen {
		if !now.Before(until) {
			delete(s.seen, id)
		}
	}
}
