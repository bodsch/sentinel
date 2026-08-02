package validator

import (
	"fmt"
	"sort"

	"bodsch.me/sentinel/internal/probe"
)

// Header checks that response headers exactly match the expected values. Header
// names are matched case-insensitively (per HTTP semantics); values are matched
// exactly. To match, for example, a Content-Type that includes a charset, the
// expected value must include it too.
type Header struct {
	expected map[string]string
}

// NewHeader returns a Header validator for the given expected header values.
func NewHeader(expected map[string]string) Header {
	return Header{expected: expected}
}

// Validate implements Validator. A mismatch classifies as validation_failed.
// Expected headers are checked in a stable (sorted) order so the reported
// detail is deterministic.
func (h Header) Validate(r *Response) Outcome {
	keys := make([]string, 0, len(h.expected))
	for k := range h.expected {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		want := h.expected[k]
		got := r.Headers.Get(k) // canonicalises the key; case-insensitive lookup
		if got != want {
			return fail(probe.ReasonValidationFailed, fmt.Sprintf("header %q = %q, want %q", k, got, want))
		}
	}
	return pass()
}

// Describe implements Validator.
func (h Header) Describe() string {
	return fmt.Sprintf("%d header(s) match", len(h.expected))
}
