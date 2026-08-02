package validator

import (
	"fmt"

	"bodsch.me/sentinel/internal/probe"
)

// Status checks that the response status code equals the expected code.
type Status struct {
	Expected int
}

// NewStatus returns a Status validator for the given expected code.
func NewStatus(expected int) Status {
	return Status{Expected: expected}
}

// Validate implements Validator. A mismatch classifies as http_status_error.
func (s Status) Validate(r *Response) Outcome {
	if r.StatusCode == s.Expected {
		return pass()
	}
	return fail(probe.ReasonHTTPStatusError, fmt.Sprintf("status %d, want %d", r.StatusCode, s.Expected))
}

// Describe implements Validator.
func (s Status) Describe() string {
	return fmt.Sprintf("status == %d", s.Expected)
}
