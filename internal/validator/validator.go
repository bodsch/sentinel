// Package validator checks an HTTP response against a target's expectations.
//
// Each Validator inspects one aspect (status code, body pattern, header) and
// reports an Outcome. On failure the Outcome also carries the stable
// FailureReason to record, so the probe need not know each validator's type:
// a status mismatch classifies as http_status_error, while body/header
// mismatches classify as validation_failed.
package validator

import (
	"net/http"

	"bodsch.me/sentinel/internal/probe"
)

// Response is the subset of an HTTP response that validators inspect.
type Response struct {
	StatusCode int
	Headers    http.Header
	// Body is the response body, already truncated to the configured
	// max_body_bytes. It is empty for HEAD requests.
	Body []byte
}

// Outcome is the result of a single validation. OK is true on success; on
// failure Reason and Detail describe what went wrong.
type Outcome struct {
	OK     bool
	Reason probe.FailureReason
	Detail string
}

// pass is the successful outcome.
func pass() Outcome { return Outcome{OK: true} }

// fail builds a failing outcome.
func fail(reason probe.FailureReason, detail string) Outcome {
	return Outcome{OK: false, Reason: reason, Detail: detail}
}

// Validator checks one aspect of a response.
type Validator interface {
	// Validate reports whether the response satisfies this expectation.
	Validate(r *Response) Outcome
	// Describe returns a short human-readable description of the check.
	Describe() string
}
