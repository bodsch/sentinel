// Package store holds the latest probe result for each target. It is the shared
// seam between the scheduler (which writes results as probes complete) and the
// metrics collector (which reads the current state live at scrape time).
//
// The store keeps only the most recent state per target — no history. Long-term
// storage is Prometheus's responsibility. The target name is the primary key;
// uniqueness is enforced earlier, during configuration validation.
//
// The store is safe for concurrent use: many probe workers write while the
// collector reads during a scrape.
package store

import (
	"sync"
	"time"

	"bodsch.me/sentinel/internal/probe"
)

// Record is a target's identity together with its latest probe result. The
// identity fields (Target, Type, Labels) are static per target; Result changes
// on every probe run. The metrics collector reads Records to emit series with
// the correct labels.
type Record struct {
	// Target is the configured target name and the store's primary key.
	Target string
	// Type is the probe protocol identifier (e.g. "http"), used as the "type"
	// metric label.
	Type string
	// Labels are the static, validated label tags for this target
	// (e.g. environment/location/service). The store treats this map as
	// read-only; callers must not mutate a map after passing it to Set.
	Labels map[string]string
	// Result is the most recent probe outcome.
	Result probe.Result
	// LastSuccess is the timestamp of the most recent successful probe. It is
	// derived and maintained by the store (carried forward across failures), so
	// callers need not set it. Zero means the target has never succeeded.
	LastSuccess time.Time
}

// Store is a concurrency-safe map of target name to its latest Record.
type Store struct {
	mu      sync.RWMutex
	records map[string]Record
}

// New returns an empty Store ready for use.
func New() *Store {
	return &Store{records: make(map[string]Record)}
}

// Set stores (or replaces) the record for r.Target. It panics if r.Target is
// empty, since a nameless record cannot be keyed or exported — an empty name is
// a programming error, not a runtime condition (config validation guarantees
// non-empty, unique names).
func (s *Store) Set(r Record) {
	if r.Target == "" {
		panic("store: Set called with empty Target")
	}
	s.mu.Lock()
	// Derive LastSuccess: set it from this result when it succeeded, otherwise
	// carry forward the previously recorded success (if any).
	if r.Result.Success {
		r.LastSuccess = r.Result.Timestamp
	} else if prev, ok := s.records[r.Target]; ok {
		r.LastSuccess = prev.LastSuccess
	}
	s.records[r.Target] = r
	s.mu.Unlock()
}

// Get returns the record for name and whether it exists. A target that has not
// completed a probe yet has no record.
func (s *Store) Get(name string) (Record, bool) {
	s.mu.RLock()
	r, ok := s.records[name]
	s.mu.RUnlock()
	return r, ok
}

// Remove deletes the record for name if present. Removed targets disappear
// immediately (no tombstone); their metrics simply stop being exported.
func (s *Store) Remove(name string) {
	s.mu.Lock()
	delete(s.records, name)
	s.mu.Unlock()
}

// Snapshot returns a copy of all records, suitable for the metrics collector to
// iterate without holding the store lock. The returned slice is freshly
// allocated; the Label maps inside are shared read-only (never mutated by the
// store), so the collector must only read them.
//
// Order is unspecified.
func (s *Store) Snapshot() []Record {
	s.mu.RLock()
	out := make([]Record, 0, len(s.records))
	for _, r := range s.records {
		out = append(out, r)
	}
	s.mu.RUnlock()
	return out
}

// Len reports the number of stored records.
func (s *Store) Len() int {
	s.mu.RLock()
	n := len(s.records)
	s.mu.RUnlock()
	return n
}
