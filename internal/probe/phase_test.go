package probe

import "testing"

func TestFailureReasonIsTimeout(t *testing.T) {
	t.Parallel()

	timeouts := map[FailureReason]bool{ReasonTimeout: true, ReasonTCPTimeout: true}
	for r := range allReasons {
		if got := r.IsTimeout(); got != timeouts[r] {
			t.Errorf("%q.IsTimeout() = %v, want %v", r, got, timeouts[r])
		}
	}
	if ReasonNone.IsTimeout() {
		t.Error("ReasonNone.IsTimeout() = true, want false")
	}
}
