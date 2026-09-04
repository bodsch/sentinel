package logging

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// decodeLines parses each non-empty line of buf as a JSON log record.
func decodeLines(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line is not valid JSON: %q: %v", line, err)
		}
		out = append(out, rec)
	}
	return out
}

// TestParseLevelRejectsUnknown is the guard on the --log-level flag. run() maps
// a ParseLevel error to exit code 2; if an unknown level silently resolved to
// info instead, an operator who deployed `--log-level=verbose` (or a typo like
// "debgu") would get a process that starts and looks healthy while logging at a
// level they did not choose — and would only find out during the incident the
// debug lines were meant for.
func TestParseLevelRejectsUnknown(t *testing.T) {
	t.Parallel()

	for _, in := range []string{"verbose", "debgu", "trace", "fatal", "0", "-1", "info,debug"} {
		if _, err := ParseLevel(in); err == nil {
			t.Errorf("ParseLevel(%q) accepted an unknown level, want an error", in)
		}
	}
}

// TestParseLevelAccepted pins the accepted spellings, including the empty string
// (the flag default, which must mean info, not an error that blocks startup) and
// the case-insensitive / padded forms an operator gets from a shell variable or
// a YAML value with trailing whitespace.
func TestParseLevelAccepted(t *testing.T) {
	t.Parallel()

	cases := map[string]slog.Level{
		"":        slog.LevelInfo,
		"info":    slog.LevelInfo,
		"INFO":    slog.LevelInfo,
		"  info ": slog.LevelInfo,
		"debug":   slog.LevelDebug,
		"Debug":   slog.LevelDebug,
		"warn":    slog.LevelWarn,
		"warning": slog.LevelWarn,
		"error":   slog.LevelError,
		"ERROR":   slog.LevelError,
	}
	for in, want := range cases {
		got, err := ParseLevel(in)
		if err != nil {
			t.Errorf("ParseLevel(%q): unexpected error %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ParseLevel(%q) = %v, want %v", in, got, want)
		}
	}
}

// TestParseFormatRejectsUnknown is the other half of the startup flag contract.
// An unknown format that silently fell back to JSON would give an operator who
// asked for "logfmt" a log stream their collector cannot parse, with no error
// telling them why.
func TestParseFormatRejectsUnknown(t *testing.T) {
	t.Parallel()

	for _, in := range []string{"logfmt", "console", "plain", "jsonl", "yaml"} {
		if _, err := ParseFormat(in); err == nil {
			t.Errorf("ParseFormat(%q) accepted an unknown format, want an error", in)
		}
	}

	cases := map[string]Format{
		"":       FormatJSON,
		"json":   FormatJSON,
		"JSON":   FormatJSON,
		" text ": FormatText,
		"Text":   FormatText,
	}
	for in, want := range cases {
		got, err := ParseFormat(in)
		if err != nil {
			t.Errorf("ParseFormat(%q): unexpected error %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ParseFormat(%q) = %v, want %v", in, got, want)
		}
	}
}

// TestNewHonoursLevel asserts the configured level actually filters. A handler
// built with the level ignored would either drown a production deployment in
// per-probe debug lines (every target, every interval, forever) or swallow the
// info-level state transitions that are the only record of when a target went
// down.
func TestNewHonoursLevel(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	l := New(&buf, Options{Level: slog.LevelInfo})
	l.Debug("suppressed")
	l.Info("kept")

	recs := decodeLines(t, &buf)
	if len(recs) != 1 {
		t.Fatalf("emitted %d records at info level, want 1 (the debug line must be dropped): %q", len(recs), buf.String())
	}
	if recs[0]["msg"] != "kept" {
		t.Errorf("emitted msg = %v, want \"kept\"", recs[0]["msg"])
	}
}

// TestNewFormats pins the encoding choice. The empty Format must mean JSON: it
// is the zero value, so a caller that forgets to set it must still get the
// machine-readable production format rather than text a log pipeline will
// mangle.
func TestNewFormats(t *testing.T) {
	t.Parallel()

	var jsonBuf, emptyBuf, textBuf bytes.Buffer
	New(&jsonBuf, Options{Format: FormatJSON}).Info("hello", "k", "v")
	New(&emptyBuf, Options{}).Info("hello", "k", "v")
	New(&textBuf, Options{Format: FormatText}).Info("hello", "k", "v")

	for name, buf := range map[string]*bytes.Buffer{"json": &jsonBuf, "empty": &emptyBuf} {
		var rec map[string]any
		if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &rec); err != nil {
			t.Errorf("%s format did not produce JSON: %q: %v", name, buf.String(), err)
			continue
		}
		if rec["k"] != "v" {
			t.Errorf("%s format lost the attribute: %v", name, rec)
		}
	}

	text := textBuf.String()
	if strings.HasPrefix(strings.TrimSpace(text), "{") {
		t.Errorf("text format produced JSON: %q", text)
	}
	if !strings.Contains(text, "k=v") {
		t.Errorf("text format = %q, want an k=v attribute", text)
	}
}

// TestWithProbeStampsIdentity checks the identity half of the documented core
// field set. These two fields are how an operator greps a specific target's
// lines out of a fleet-wide stream; if a rename left one call site spelling it
// "probeType" and another "probe_type", that grep would silently return half
// the lines.
func TestWithProbeStampsIdentity(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	l := WithProbe(New(&buf, Options{Level: slog.LevelDebug}), "api-prod", "http")
	l.Info("first")
	l.Info("second")

	recs := decodeLines(t, &buf)
	if len(recs) != 2 {
		t.Fatalf("got %d records, want 2", len(recs))
	}
	for i, rec := range recs {
		if rec[FieldTarget] != "api-prod" {
			t.Errorf("record %d: %s = %v, want \"api-prod\"", i, FieldTarget, rec[FieldTarget])
		}
		if rec[FieldProbeType] != "http" {
			t.Errorf("record %d: %s = %v, want \"http\"", i, FieldProbeType, rec[FieldProbeType])
		}
	}
}

// TestWithResultStampsOutcome checks the outcome half, and specifically that the
// duration is emitted as whole milliseconds under "duration_ms". A logger that
// stamped a Duration value instead would write "1.5s" in text output and
// 1500000000 in JSON on the same field, so a dashboard or alert built on
// duration_ms would read nanoseconds as milliseconds and be off by 10^6.
func TestWithResultStampsOutcome(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	l := WithResult(New(&buf, Options{Level: slog.LevelDebug}), false, 1500*time.Millisecond)
	l.Info("done")

	recs := decodeLines(t, &buf)
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	rec := recs[0]
	if rec[FieldSuccess] != false {
		t.Errorf("%s = %v, want false", FieldSuccess, rec[FieldSuccess])
	}
	// JSON numbers decode as float64; 1500 ms, not 1.5 or 1.5e9.
	if got, ok := rec[FieldDurationMs].(float64); !ok || got != 1500 {
		t.Errorf("%s = %v (%T), want 1500 whole milliseconds", FieldDurationMs, rec[FieldDurationMs], rec[FieldDurationMs])
	}
}

// TestWithProbeDoesNotMutateParent guards against the derived loggers being
// built by mutating a shared parent. Sentinel derives one logger per target from
// a single root; if With() leaked upward, every target's lines would end up
// carrying the last-registered target's name and the logs would attribute
// failures to the wrong endpoint.
func TestWithProbeDoesNotMutateParent(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	root := New(&buf, Options{Level: slog.LevelDebug})
	_ = WithResult(WithProbe(root, "api-prod", "http"), true, time.Second)
	root.Info("plain")

	recs := decodeLines(t, &buf)
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	for _, f := range []string{FieldTarget, FieldProbeType, FieldSuccess, FieldDurationMs} {
		if _, present := recs[0][f]; present {
			t.Errorf("deriving a probe logger leaked %q onto the root logger: %v", f, recs[0])
		}
	}
}
