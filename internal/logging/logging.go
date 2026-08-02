// Package logging centralises Sentinel's structured logging. All logging goes
// through log/slog with a uniform field schema; no other package should build
// handlers or call slog.Default directly.
//
// Convention: probe-related log lines carry a fixed core field set — "target",
// "probe_type", "success", "duration_ms", "failure_reason", "phase" — attached
// once via a derived logger (see WithProbe) rather than repeated at each call
// site. Successful probes log at debug; failures and state changes at info.
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"strings"
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

// WithProbe returns a logger that stamps the fixed per-probe core fields on every
// line, so call sites do not repeat them. target is the target name and
// probeType is the protocol identifier (e.g. "http").
func WithProbe(l *slog.Logger, target, probeType string) *slog.Logger {
	return l.With(
		slog.String("target", target),
		slog.String("probe_type", probeType),
	)
}
