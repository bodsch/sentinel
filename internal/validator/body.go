package validator

import (
	"fmt"
	"regexp"

	"bodsch.me/sentinel/internal/probe"
)

// BodyRegex checks that the response body matches every configured pattern. All
// patterns must match (logical AND).
type BodyRegex struct {
	patterns []*regexp.Regexp
}

// NewBodyRegex returns a BodyRegex validator. Patterns must be pre-compiled by
// the caller (configuration validation already compiles them once).
func NewBodyRegex(patterns []*regexp.Regexp) BodyRegex {
	return BodyRegex{patterns: patterns}
}

// Validate implements Validator. A non-matching pattern classifies as
// validation_failed. Matching runs against the (possibly truncated) body, so a
// pattern that would only match beyond max_body_bytes will fail.
func (b BodyRegex) Validate(r *Response) Outcome {
	for _, re := range b.patterns {
		if !re.Match(r.Body) {
			return fail(probe.ReasonValidationFailed, fmt.Sprintf("body does not match %q", re.String()))
		}
	}
	return pass()
}

// Describe implements Validator.
func (b BodyRegex) Describe() string {
	return fmt.Sprintf("body matches %d pattern(s)", len(b.patterns))
}
