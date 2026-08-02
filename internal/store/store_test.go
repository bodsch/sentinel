package store

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"bodsch.me/sentinel/internal/probe"
)

func rec(name string, success bool) Record {
	return Record{
		Target: name,
		Type:   "http",
		Labels: map[string]string{"environment": "test"},
		Result: probe.Result{
			Success:   success,
			Timestamp: time.Unix(0, 0),
		},
	}
}

func TestEmptyStore(t *testing.T) {
	t.Parallel()

	s := New()
	if got := s.Len(); got != 0 {
		t.Fatalf("Len() = %d, want 0", got)
	}
	if _, ok := s.Get("nope"); ok {
		t.Fatal("Get on empty store returned ok=true")
	}
	if got := s.Snapshot(); len(got) != 0 {
		t.Fatalf("Snapshot() len = %d, want 0", len(got))
	}
}

func TestSetGet(t *testing.T) {
	t.Parallel()

	s := New()
	s.Set(rec("homepage", true))

	got, ok := s.Get("homepage")
	if !ok {
		t.Fatal("Get returned ok=false after Set")
	}
	if !got.Result.Success {
		t.Error("stored result success = false, want true")
	}
	if got.Type != "http" {
		t.Errorf("type = %q, want http", got.Type)
	}
	if got, want := s.Len(), 1; got != want {
		t.Errorf("Len() = %d, want %d", got, want)
	}
}

func TestSetReplaces(t *testing.T) {
	t.Parallel()

	s := New()
	s.Set(rec("api", true))
	s.Set(rec("api", false)) // same key, newer state

	got, _ := s.Get("api")
	if got.Result.Success {
		t.Error("expected the replacement (success=false) to win")
	}
	if got, want := s.Len(), 1; got != want {
		t.Errorf("Len() = %d, want %d (replace must not add a key)", got, want)
	}
}

func TestSetEmptyTargetPanics(t *testing.T) {
	t.Parallel()

	s := New()
	defer func() {
		if recover() == nil {
			t.Fatal("Set with empty Target did not panic")
		}
	}()
	s.Set(Record{Target: ""})
}

func TestRemove(t *testing.T) {
	t.Parallel()

	s := New()
	s.Set(rec("gone", true))
	s.Remove("gone")

	if _, ok := s.Get("gone"); ok {
		t.Error("record still present after Remove")
	}
	if got := s.Len(); got != 0 {
		t.Errorf("Len() = %d after Remove, want 0", got)
	}
	// Removing a missing key is a no-op, not an error.
	s.Remove("never-existed")
}

func TestSnapshotIsIndependentCopy(t *testing.T) {
	t.Parallel()

	s := New()
	s.Set(rec("a", true))
	s.Set(rec("b", false))

	snap := s.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("Snapshot len = %d, want 2", len(snap))
	}

	// Mutating the returned slice must not affect the store.
	snap[0] = rec("mutated", true)
	if _, ok := s.Get("mutated"); ok {
		t.Error("mutating the snapshot slice leaked into the store")
	}
	if got := s.Len(); got != 2 {
		t.Errorf("store Len changed to %d after mutating snapshot", got)
	}
}

func TestLastSuccessCarriedForward(t *testing.T) {
	t.Parallel()

	s := New()
	successTime := time.Unix(1000, 0)

	// A success sets LastSuccess to the result timestamp.
	s.Set(Record{Target: "x", Type: "http", Result: probe.Result{Success: true, Timestamp: successTime}})
	if rec, _ := s.Get("x"); !rec.LastSuccess.Equal(successTime) {
		t.Fatalf("LastSuccess = %v, want %v", rec.LastSuccess, successTime)
	}

	// A subsequent failure carries the previous success forward.
	s.Set(Record{Target: "x", Type: "http", Result: probe.Result{Success: false, Timestamp: time.Unix(2000, 0)}})
	rec, _ := s.Get("x")
	if !rec.LastSuccess.Equal(successTime) {
		t.Errorf("after failure LastSuccess = %v, want carried-forward %v", rec.LastSuccess, successTime)
	}
	if rec.Result.Success {
		t.Error("current result should reflect the failure")
	}

	// A target that has only ever failed has a zero LastSuccess.
	s.Set(Record{Target: "y", Type: "http", Result: probe.Result{Success: false, Timestamp: time.Unix(3000, 0)}})
	if rec, _ := s.Get("y"); !rec.LastSuccess.IsZero() {
		t.Errorf("never-successful target LastSuccess = %v, want zero", rec.LastSuccess)
	}
}

// TestConcurrentAccess exercises the store under concurrent writers and readers;
// it is meaningful under `go test -race`.
func TestConcurrentAccess(t *testing.T) {
	t.Parallel()

	s := New()
	const workers = 8
	const iterations = 500

	var wg sync.WaitGroup

	// Writers: each owns a distinct set of target names.
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				name := fmt.Sprintf("t-%d-%d", w, i%10)
				s.Set(rec(name, i%2 == 0))
			}
		}(w)
	}

	// Readers: snapshot and point-read concurrently.
	for r := 0; r < workers; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				for _, rec := range s.Snapshot() {
					_ = rec.Result.Success
					_ = rec.Labels["environment"]
				}
				_, _ = s.Get("t-0-0")
				_ = s.Len()
			}
		}()
	}

	wg.Wait()

	if got := s.Len(); got != workers*10 {
		t.Fatalf("Len() = %d, want %d", got, workers*10)
	}
}
