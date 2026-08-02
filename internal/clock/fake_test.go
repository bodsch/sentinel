package clock

import (
	"testing"
	"time"
)

var epoch = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func TestFakeNowAdvance(t *testing.T) {
	t.Parallel()

	f := NewFake(epoch)
	if got := f.Now(); !got.Equal(epoch) {
		t.Fatalf("Now() = %v, want %v", got, epoch)
	}
	f.Advance(90 * time.Second)
	if got, want := f.Now(), epoch.Add(90*time.Second); !got.Equal(want) {
		t.Fatalf("after Advance Now() = %v, want %v", got, want)
	}
}

func TestFakeTickerFires(t *testing.T) {
	t.Parallel()

	f := NewFake(epoch)
	tk := f.NewTicker(30 * time.Second)
	defer tk.Stop()

	// Not yet due.
	select {
	case <-tk.C():
		t.Fatal("ticker fired before its interval elapsed")
	default:
	}

	f.Advance(30 * time.Second)
	select {
	case tick := <-tk.C():
		if want := epoch.Add(30 * time.Second); !tick.Equal(want) {
			t.Fatalf("tick time = %v, want %v", tick, want)
		}
	default:
		t.Fatal("ticker did not fire after its interval elapsed")
	}
}

func TestFakeTickerStop(t *testing.T) {
	t.Parallel()

	f := NewFake(epoch)
	tk := f.NewTicker(10 * time.Second)
	tk.Stop()

	f.Advance(60 * time.Second)
	select {
	case <-tk.C():
		t.Fatal("stopped ticker fired")
	default:
	}
}

func TestFakeAfter(t *testing.T) {
	t.Parallel()

	f := NewFake(epoch)
	ch := f.After(5 * time.Second)

	f.Advance(4 * time.Second)
	select {
	case <-ch:
		t.Fatal("After fired early")
	default:
	}

	f.Advance(1 * time.Second)
	select {
	case <-ch:
	default:
		t.Fatal("After did not fire at its deadline")
	}
}
