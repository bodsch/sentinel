// Package logging centralises Sentinel's structured logging. All logging goes
// through log/slog with a uniform field schema; no other package should build
// handlers or call slog.Default directly.
//
// Convention: probe-related log lines carry a fixed core field set, and the
// field names live here rather than at each call site, so a rename cannot leave
// two spellings of the same field in the output. The set is split by when the
// values become known:
//
//   - identity, known before the probe runs: "target", "probe_type" (WithProbe)
//   - outcome, known after it finishes: "success", "duration_ms" (WithResult)
//   - "failure_reason" stays at the call site: it is meaningful only on the
//     failure lines, and stamping it on a success line would emit "none".
//   - "phase" likewise: present only on a timeout failure, naming the phase
//     that was in progress (dns, connect, tls, ttfb, download, banner). See
//     FailureAttrs.
//
// Successful probes log at debug; failures and state changes at info.
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"
)

// Field names of the per-probe core set. Exported so callers assert against the
// constant rather than a duplicated string literal.
const (
	// FieldTarget is the configured target name.
	FieldTarget = "target"
	// FieldProbeType is the protocol identifier (e.g. "http").
	FieldProbeType = "probe_type"
	// FieldSuccess reports whether the check passed.
	FieldSuccess = "success"
	// FieldDurationMs is the probe wall-clock duration in whole milliseconds.
	FieldDurationMs = "duration_ms"
	// FieldFailureReason is the stable failure enum, present only on failure
	// lines.
	FieldFailureReason = "failure_reason"
	// FieldPhase is the phase a timed-out probe was stuck in, present only on
	// timeout failure lines.
	FieldPhase = "phase"
)

// Format selects the handler output encoding.
type Format string

const (
	// FormatJSON is the production default: one JSON object per line.
	FormatJSON Format = "json"
	// FormatText is a human-friendly format for local development.
	FormatText Format = "text"
)

// Options configures the root logger.
type Options struct {
	// Level is the minimum level to emit (e.g. slog.LevelInfo).
	Level slog.Level
	// Format selects JSON or text output. Empty means FormatJSON.
	Format Format
}

// New builds a root *slog.Logger writing to w using opts. It does not modify the
// global slog default; callers pass the returned logger explicitly.
func New(w io.Writer, opts Options) *slog.Logger {
	handlerOpts := &slog.HandlerOptions{Level: opts.Level}

	var handler slog.Handler
	switch opts.Format {
	case FormatText:
		handler = slog.NewTextHandler(w, handlerOpts)
	default: // FormatJSON and the empty value
		handler = slog.NewJSONHandler(w, handlerOpts)
	}
	return slog.New(handler)
}

// ParseLevel converts a case-insensitive level name ("debug", "info", "warn",
// "error") into an slog.Level. Unknown values return an error.
func ParseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug, nil
	case "info", "":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("logging: unknown level %q", s)
	}
}

// ParseFormat converts a case-insensitive format name into a Format. Unknown
// values return an error.
func ParseFormat(s string) (Format, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "json", "":
		return FormatJSON, nil
	case "text":
		return FormatText, nil
	default:
		return FormatJSON, fmt.Errorf("logging: unknown format %q", s)
	}
}

// WithProbe returns a logger that stamps a probe's identity fields on every
// line, so call sites do not repeat them.
//
// Parameters:
//   - l: the parent logger.
//   - target: the configured target name.
//   - probeType: the protocol identifier (e.g. "http").
//
// It returns a derived logger; the parent is unchanged.
func WithProbe(l *slog.Logger, target, probeType string) *slog.Logger {
	return l.With(
		slog.String(FieldTarget, target),
		slog.String(FieldProbeType, probeType),
	)
}

// FailureAttrs returns the attributes of a failure line: the failure reason and,
// when the probe recorded one, the phase it timed out in. An empty phase is
// omitted rather than logged as "", so the field's presence alone means "this
// timeout was attributed".
//
// Parameters:
//   - reason: the stable failure reason.
//   - phase: the timeout phase; empty for non-timeout failures.
//
// It returns the attributes in a fixed order, ready to pass to a log call.
func FailureAttrs(reason, phase string) []any {
	attrs := []any{slog.String(FieldFailureReason, reason)}
	if phase != "" {
		attrs = append(attrs, slog.String(FieldPhase, phase))
	}
	return attrs
}

// WithResult returns a logger that stamps a completed probe's outcome fields.
// It is the second half of the core set (see WithProbe) and exists so the
// duration is rendered the same way — whole milliseconds under
// "duration_ms" — on every line that reports one.
//
// Parameters:
//   - l: the parent logger, usually already derived via WithProbe.
//   - success: whether the check passed.
//   - duration: the probe's wall-clock duration; truncated to whole
//     milliseconds.
//
// It returns a derived logger; the parent is unchanged.
func WithResult(l *slog.Logger, success bool, duration time.Duration) *slog.Logger {
	return l.With(
		slog.Bool(FieldSuccess, success),
		slog.Int64(FieldDurationMs, duration.Milliseconds()),
	)
}
