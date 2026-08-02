package validator

import (
	"net/http"
	"regexp"
	"testing"

	"bodsch.me/sentinel/internal/probe"
)

func TestStatusValidator(t *testing.T) {
	t.Parallel()

	v := NewStatus(200)
	if out := v.Validate(&Response{StatusCode: 200}); !out.OK {
		t.Fatalf("expected pass for matching status, got %+v", out)
	}
	out := v.Validate(&Response{StatusCode: 500})
	if out.OK {
		t.Fatal("expected failure for mismatched status")
	}
	if out.Reason != probe.ReasonHTTPStatusError {
		t.Errorf("reason = %q, want %q", out.Reason, probe.ReasonHTTPStatusError)
	}
}

func TestBodyRegexValidator(t *testing.T) {
	t.Parallel()

	v := NewBodyRegex([]*regexp.Regexp{
		regexp.MustCompile(`healthy`),
		regexp.MustCompile(`"code"\s*:\s*0`),
	})

	if out := v.Validate(&Response{Body: []byte(`{"status":"healthy","code": 0}`)}); !out.OK {
		t.Fatalf("expected pass, got %+v", out)
	}

	out := v.Validate(&Response{Body: []byte(`{"status":"healthy"}`)}) // second pattern missing
	if out.OK {
		t.Fatal("expected failure when one pattern does not match")
	}
	if out.Reason != probe.ReasonValidationFailed {
		t.Errorf("reason = %q, want %q", out.Reason, probe.ReasonValidationFailed)
	}
}

func TestHeaderValidator(t *testing.T) {
	t.Parallel()

	h := http.Header{}
	h.Set("Content-Type", "application/json")
	h.Set("X-Service", "frontend")

	v := NewHeader(map[string]string{
		"content-type": "application/json", // case-insensitive key lookup
		"X-Service":    "frontend",
	})
	if out := v.Validate(&Response{Headers: h}); !out.OK {
		t.Fatalf("expected pass, got %+v", out)
	}

	mismatch := NewHeader(map[string]string{"Content-Type": "text/html"})
	out := mismatch.Validate(&Response{Headers: h})
	if out.OK {
		t.Fatal("expected failure for header value mismatch")
	}
	if out.Reason != probe.ReasonValidationFailed {
		t.Errorf("reason = %q, want %q", out.Reason, probe.ReasonValidationFailed)
	}
}

func TestHeaderExactMatchNotSubstring(t *testing.T) {
	t.Parallel()

	h := http.Header{}
	h.Set("Content-Type", "text/html; charset=utf-8")

	// Exact-match semantics: "text/html" must NOT match "text/html; charset=utf-8".
	v := NewHeader(map[string]string{"Content-Type": "text/html"})
	if out := v.Validate(&Response{Headers: h}); out.OK {
		t.Fatal("expected exact-match failure, but it passed (substring match?)")
	}
}

// Ensure the concrete validators satisfy the interface.
var (
	_ Validator = Status{}
	_ Validator = BodyRegex{}
	_ Validator = Header{}
)
