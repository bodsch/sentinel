package validator

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/ohler55/ojg/jp"

	"bodsch.me/sentinel/internal/probe"
)

// JSONPathCheck is a single compiled JSONPath assertion.
type JSONPathCheck struct {
	// Expr is the compiled JSONPath expression.
	Expr jp.Expr
	// Path is the original path text, kept for failure messages.
	Path string
	// Equals, when non-nil, requires the resolved scalar value (as a string) to
	// equal it. When nil the check only requires the path to resolve.
	Equals *string
}

// JSONPath validates a JSON response body against a set of JSONPath assertions.
// The body must parse as JSON; each path must resolve; and when a check sets
// Equals, the first resolved scalar value (compared as a string) must equal it.
type JSONPath struct {
	checks []JSONPathCheck
}

// NewJSONPath returns a JSONPath validator over pre-compiled checks (config
// validation and the prober compile the paths once already).
func NewJSONPath(checks []JSONPathCheck) JSONPath {
	return JSONPath{checks: checks}
}

// Validate implements Validator. A body that is not valid JSON, a path that does
// not resolve, or a scalar that does not equal the expected value all classify
// as validation_failed.
func (j JSONPath) Validate(r *Response) Outcome {
	var data any
	dec := json.NewDecoder(bytes.NewReader(r.Body))
	// UseNumber keeps integers exact (no float64 rounding) so equality checks on
	// large numbers compare their original text.
	dec.UseNumber()
	if err := dec.Decode(&data); err != nil {
		// A body larger than max_body_bytes is truncated before it reaches here,
		// which makes valid-but-large JSON fail to decode; the message hints at it.
		return fail(probe.ReasonValidationFailed, "response body is not valid JSON (or was truncated by max_body_bytes)")
	}
	// json.Decoder consumes only the first value; reject trailing content so
	// "{...}<junk>" is not accepted as valid JSON.
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return fail(probe.ReasonValidationFailed, "response body has trailing data after the JSON value")
	}

	for _, c := range j.checks {
		// Get returns every matching node (a path may match several via a wildcard
		// or filter), so an existence check needs one match and an equals check
		// requires *all* matched scalars to satisfy it.
		results := c.Expr.Get(data)
		if len(results) == 0 {
			return fail(probe.ReasonValidationFailed, fmt.Sprintf("json path %q did not resolve", c.Path))
		}
		if c.Equals == nil {
			continue // existence check only
		}
		for _, v := range results {
			if !scalarEquals(v, *c.Equals) {
				got, _ := scalarString(v)
				return fail(probe.ReasonValidationFailed, fmt.Sprintf("json path %q = %q, want %q", c.Path, got, *c.Equals))
			}
		}
	}
	return pass()
}

// scalarEquals reports whether the scalar JSON value v equals the expected
// string. Strings, bools and null compare textually; numbers compare
// numerically (so 200, 200.0 and 2e2 all match "200"), after an exact-text fast
// path that keeps large integers precise.
func scalarEquals(v any, expected string) bool {
	s, ok := scalarString(v)
	if !ok {
		return false // arrays/objects are not scalars
	}
	if s == expected {
		return true
	}
	if isNumber(v) {
		if a, err := strconv.ParseFloat(s, 64); err == nil {
			if b, err := strconv.ParseFloat(strings.TrimSpace(expected), 64); err == nil {
				return a == b
			}
		}
	}
	return false
}

// isNumber reports whether v is a JSON number.
func isNumber(v any) bool {
	switch v.(type) {
	case json.Number, float64:
		return true
	}
	return false
}

// Describe implements Validator.
func (j JSONPath) Describe() string {
	return fmt.Sprintf("json satisfies %d path assertion(s)", len(j.checks))
}

// scalarString renders a scalar JSON value as a string for equality comparison.
// Arrays and objects are not scalars and return ok=false.
func scalarString(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, true
	case bool:
		return strconv.FormatBool(x), true
	case json.Number:
		return x.String(), true
	case float64:
		return strconv.FormatFloat(x, 'g', -1, 64), true
	case nil:
		return "null", true
	default:
		return "", false
	}
}
