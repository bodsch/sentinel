package validator

import (
	"testing"

	"github.com/ohler55/ojg/jp"

	"bodsch.me/sentinel/internal/probe"
)

func strp(s string) *string { return &s }

func mustCheck(t *testing.T, path string, equals *string) JSONPathCheck {
	t.Helper()
	e, err := jp.ParseString(path)
	if err != nil {
		t.Fatalf("parse %q: %v", path, err)
	}
	return JSONPathCheck{Expr: e, Path: path, Equals: equals}
}

func TestJSONPathValidate(t *testing.T) {
	t.Parallel()

	body := []byte(`{
		"status":"ok","code":200,"active":true,"empty":"","nothing":null,
		"data":{"items":[1,2,3]},
		"all":[{"s":"ok"},{"s":"ok"}],
		"mixed":[{"s":"ok"},{"s":"err"}]
	}`)

	tests := []struct {
		name   string
		checks []JSONPathCheck
		ok     bool
	}{
		{"exists", []JSONPathCheck{mustCheck(t, "$.status", nil)}, true},
		{"equals string", []JSONPathCheck{mustCheck(t, "$.status", strp("ok"))}, true},
		{"equals string mismatch", []JSONPathCheck{mustCheck(t, "$.status", strp("nope"))}, false},
		{"equals number exact", []JSONPathCheck{mustCheck(t, "$.code", strp("200"))}, true},
		{"equals number decimal form", []JSONPathCheck{mustCheck(t, "$.code", strp("200.0"))}, true},
		{"equals number exponent form", []JSONPathCheck{mustCheck(t, "$.code", strp("2e2"))}, true},
		{"equals number mismatch", []JSONPathCheck{mustCheck(t, "$.code", strp("201"))}, false},
		{"equals bool", []JSONPathCheck{mustCheck(t, "$.active", strp("true"))}, true},
		{"equals empty string", []JSONPathCheck{mustCheck(t, "$.empty", strp(""))}, true},
		{"null exists", []JSONPathCheck{mustCheck(t, "$.nothing", nil)}, true},
		{"null equals", []JSONPathCheck{mustCheck(t, "$.nothing", strp("null"))}, true},
		{"path missing", []JSONPathCheck{mustCheck(t, "$.missing", nil)}, false},
		{"nested array index", []JSONPathCheck{mustCheck(t, "$.data.items[1]", strp("2"))}, true},
		{"non-scalar equals fails", []JSONPathCheck{mustCheck(t, "$.data.items", strp("x"))}, false},
		{"multi-match all satisfy", []JSONPathCheck{mustCheck(t, "$.all[*].s", strp("ok"))}, true},
		{"multi-match one fails", []JSONPathCheck{mustCheck(t, "$.mixed[*].s", strp("ok"))}, false},
		{"all-of multiple", []JSONPathCheck{mustCheck(t, "$.status", strp("ok")), mustCheck(t, "$.code", strp("200"))}, true},
		{"one-of multiple fails", []JSONPathCheck{mustCheck(t, "$.status", strp("ok")), mustCheck(t, "$.code", strp("500"))}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := NewJSONPath(tc.checks).Validate(&Response{Body: body})
			if out.OK != tc.ok {
				t.Fatalf("OK = %v (%s), want %v", out.OK, out.Detail, tc.ok)
			}
			if !out.OK && out.Reason != probe.ReasonValidationFailed {
				t.Errorf("reason = %q, want validation_failed", out.Reason)
			}
		})
	}
}

func TestJSONPathInvalidBody(t *testing.T) {
	t.Parallel()

	cases := map[string][]byte{
		"not json":      []byte("not json"),
		"trailing junk": []byte(`{"status":"ok"}<!-- footer -->`),
		"two values":    []byte(`{"a":1}{"b":2}`),
		"empty (HEAD)":  []byte(""),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			out := NewJSONPath([]JSONPathCheck{mustCheck(t, "$.status", strp("ok"))}).Validate(&Response{Body: body})
			if out.OK {
				t.Fatalf("expected failure for %q body", name)
			}
			if out.Reason != probe.ReasonValidationFailed {
				t.Errorf("reason = %q, want validation_failed", out.Reason)
			}
		})
	}
}
