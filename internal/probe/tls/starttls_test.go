package tls

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"bodsch.me/sentinel/internal/probe"
	"bodsch.me/sentinel/internal/store"
)

// dialogue is the server side of a STARTTLS exchange. It returns true when the
// server agreed to upgrade and the TLS handshake should follow.
type dialogue func(r *bufio.Reader, w io.Writer) bool

// startTLSServer is a plaintext listener that runs a scripted dialogue and, on
// agreement, upgrades the same connection to TLS.
type startTLSServer struct {
	host string
	port int
	// afterTLS receives everything the client sent over TLS after the
	// handshake, i.e. its goodbye.
	afterTLS chan []byte
}

// newStartTLSServer starts the listener and stops it when the test ends.
//
// Parameters:
//   - t: the test.
//   - cfg: the TLS configuration used after the upgrade.
//   - script: the plaintext dialogue to run on each connection.
func newStartTLSServer(t *testing.T, cfg *tls.Config, script dialogue) *startTLSServer {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	done := make(chan struct{})
	t.Cleanup(func() { close(done); _ = ln.Close() })

	addr := ln.Addr().(*net.TCPAddr)
	srv := &startTLSServer{host: addr.IP.String(), port: addr.Port, afterTLS: make(chan []byte, 4)}

	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				// A dialogue that stalls on purpose is released when the test ends.
				go func() { <-done; _ = conn.Close() }()

				r := bufio.NewReader(conn)
				if !script(r, conn) {
					return
				}
				tc := tls.Server(conn, cfg)
				if tc.Handshake() != nil {
					return
				}
				_ = tc.SetReadDeadline(time.Now().Add(2 * time.Second))
				rest, _ := io.ReadAll(io.LimitReader(tc, 1024))
				srv.afterTLS <- rest
			}()
		}
	}()
	return srv
}

// options returns probe options for the server with the given dialogue.
func (s *startTLSServer) options(proto StartTLS) Options {
	return Options{
		Name:       "starttls",
		Host:       s.host,
		Port:       s.port,
		Timeout:    3 * time.Second,
		ServerName: testHost,
		StartTLS:   proto,
	}
}

// readCmd reads one client command line, without CRLF.
func readCmd(r *bufio.Reader) string {
	line, _ := r.ReadString('\n')
	return strings.TrimRight(line, "\r\n")
}

// smtpScript is a well-behaved submission server.
func smtpScript(ehlo []string, starttlsReply string) dialogue {
	return func(r *bufio.Reader, w io.Writer) bool {
		_, _ = io.WriteString(w, "220-mail.example ESMTP\r\n220 ready\r\n")
		if !strings.HasPrefix(readCmd(r), "EHLO ") {
			return false
		}
		for i, l := range ehlo {
			sep := "-"
			if i == len(ehlo)-1 {
				sep = " "
			}
			_, _ = io.WriteString(w, "250"+sep+l+"\r\n")
		}
		if readCmd(r) != "STARTTLS" {
			return false
		}
		_, _ = io.WriteString(w, starttlsReply)
		return strings.HasPrefix(starttlsReply, "220")
	}
}

// ber encodes one TLV; long forces the four-octet length form Active Directory
// uses.
func ber(tag byte, long bool, content ...[]byte) []byte {
	body := bytes.Join(content, nil)
	out := []byte{tag}
	if long {
		n := len(body)
		out = append(out, 0x84, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	} else {
		out = append(out, byte(len(body)))
	}
	return append(out, body...)
}

// ldapResponse builds an extended response with the given messageID and
// resultCode.
func ldapResponse(id, code byte, diagnostic string, long bool) []byte {
	return ber(0x30, long,
		ber(0x02, false, []byte{id}),
		ber(0x78, long,
			ber(0x0a, false, []byte{code}),
			ber(0x04, false),
			ber(0x04, false, []byte(diagnostic)),
		),
	)
}

// ldapScript answers the StartTLS request with resp, after checking the request
// is byte-exact.
func ldapScript(resp []byte) dialogue {
	return func(r *bufio.Reader, w io.Writer) bool {
		req := make([]byte, len(ldapStartTLSRequest))
		if _, err := io.ReadFull(r, req); err != nil || !bytes.Equal(req, ldapStartTLSRequest) {
			return false
		}
		_, _ = w.Write(resp)
		return bytes.Equal(resp, ldapResponse(1, 0, "", true)) || bytes.Equal(resp, ldapResponse(1, 0, "", false))
	}
}

func TestStartTLSSuccess(t *testing.T) {
	t.Parallel()

	ca := newAuthority(t, "Sentinel STARTTLS Test CA")
	cfg := serverConfig(ca.issue(t, leafOptions{}))

	tests := []struct {
		name    string
		proto   StartTLS
		script  dialogue
		goodbye []byte
	}{
		{
			name:  "smtp with multi-line greeting and EHLO",
			proto: StartTLSSMTP,
			// STARTTLS in the middle and in lowercase: position and case must
			// not matter.
			script:  smtpScript([]string{"mail.example", "PIPELINING", "starttls", "SIZE 10240000"}, "220 go ahead\r\n"),
			goodbye: []byte("QUIT\r\n"),
		},
		{
			name:  "imap with untagged data before the tagged reply",
			proto: StartTLSIMAP,
			script: func(r *bufio.Reader, w io.Writer) bool {
				_, _ = io.WriteString(w, "* OK [CAPABILITY IMAP4rev1 STARTTLS] ready\r\n")
				if readCmd(r) != "a001 STARTTLS" {
					return false
				}
				_, _ = io.WriteString(w, "* CAPABILITY IMAP4rev1\r\na001 OK Begin TLS negotiation now\r\n")
				return true
			},
			goodbye: []byte("a002 LOGOUT\r\n"),
		},
		{
			name:  "pop3",
			proto: StartTLSPOP3,
			script: func(r *bufio.Reader, w io.Writer) bool {
				_, _ = io.WriteString(w, "+OK POP3 ready\r\n")
				if readCmd(r) != "STLS" {
					return false
				}
				_, _ = io.WriteString(w, "+OK Begin TLS negotiation\r\n")
				return true
			},
			goodbye: []byte("QUIT\r\n"),
		},
		{
			name:    "ldap with short-form lengths",
			proto:   StartTLSLDAP,
			script:  ldapScript(ldapResponse(1, 0, "", false)),
			goodbye: []byte{0x30, 0x05, 0x02, 0x01, 0x02, 0x42, 0x00},
		},
		{
			name:    "ldap with Active Directory's four-octet lengths",
			proto:   StartTLSLDAP,
			script:  ldapScript(ldapResponse(1, 0, "", true)),
			goodbye: []byte{0x30, 0x05, 0x02, 0x01, 0x02, 0x42, 0x00},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv := newStartTLSServer(t, cfg, tc.script)
			opts := srv.options(tc.proto)
			opts.Roots = ca.pool

			res := runProbe(t, opts)
			if !res.Success {
				t.Fatalf("probe failed: %q", res.FailureReason)
			}
			d := diag(t, res)
			if d.StartTLS != tc.proto {
				t.Errorf("diagnostics starttls = %q, want %q", d.StartTLS, tc.proto)
			}
			if d.StartTLSDuration <= 0 {
				t.Error("starttls duration not recorded")
			}
			if d.TLS == nil || !d.TLS.Valid || !d.TLS.ChainVerified {
				t.Errorf("certificate behind STARTTLS not inspected: %+v", d.TLS)
			}
			if res.Timings.TLS <= 0 || res.Timings.Connect <= 0 {
				t.Errorf("phase timings missing: %+v", res.Timings)
			}

			select {
			case got := <-srv.afterTLS:
				if !bytes.Equal(got, tc.goodbye) {
					t.Errorf("goodbye = %q, want %q", got, tc.goodbye)
				}
			case <-time.After(3 * time.Second):
				t.Error("server never saw the end of the session")
			}
		})
	}
}

func TestStartTLSRefusals(t *testing.T) {
	t.Parallel()

	ca := newAuthority(t, "Sentinel STARTTLS Test CA")
	cfg := serverConfig(ca.issue(t, leafOptions{}))

	lines := func(s string) dialogue {
		return func(_ *bufio.Reader, w io.Writer) bool {
			_, _ = io.WriteString(w, s)
			return false
		}
	}
	reply := func(greeting, answer string) dialogue {
		return func(r *bufio.Reader, w io.Writer) bool {
			_, _ = io.WriteString(w, greeting)
			readCmd(r)
			_, _ = io.WriteString(w, answer)
			return false
		}
	}

	tests := []struct {
		name   string
		proto  StartTLS
		script dialogue
	}{
		{"smtp greeting refuses the connection", StartTLSSMTP, lines("554 no service\r\n")},
		{"smtp greeting is not SMTP", StartTLSSMTP, lines("SSH-2.0-OpenSSH_9.6\r\n")},
		{"smtp does not offer STARTTLS", StartTLSSMTP,
			smtpScript([]string{"mail.example", "PIPELINING", "AUTH PLAIN"}, "")},
		{"smtp rejects STARTTLS", StartTLSSMTP,
			smtpScript([]string{"mail.example", "STARTTLS"}, "454 TLS not available\r\n")},
		{"smtp mixes reply codes in one reply", StartTLSSMTP, lines("220-ready\r\n250 ready\r\n")},
		{"smtp reply line too long", StartTLSSMTP, lines("220 " + strings.Repeat("x", maxLineBytes) + "\r\n")},
		{"smtp endless continuation lines", StartTLSSMTP, lines(strings.Repeat("220-more\r\n", maxReplyLines+1))},
		{"imap preauth forbids STARTTLS", StartTLSIMAP, lines("* PREAUTH logged in\r\n")},
		{"imap rejects STARTTLS", StartTLSIMAP, reply("* OK ready\r\n", "a001 NO not now\r\n")},
		{"pop3 rejects STLS", StartTLSPOP3, reply("+OK ready\r\n", "-ERR not supported\r\n")},
		{"pop3 greeting is an error", StartTLSPOP3, lines("-ERR go away\r\n")},
		{"ldap result is not success", StartTLSLDAP, ldapScript(ldapResponse(1, 2, "unsupported extended operation", false))},
		{"ldap notice of disconnection", StartTLSLDAP, ldapScript(ldapResponse(0, 52, "unavailable", false))},
		{"ldap length field beyond the cap", StartTLSLDAP, func(r *bufio.Reader, w io.Writer) bool {
			_, _ = io.ReadFull(r, make([]byte, len(ldapStartTLSRequest)))
			_, _ = w.Write([]byte{0x30, 0x84, 0x7f, 0xff, 0xff, 0xff})
			return false
		}},
		{"plaintext injected after the agreement", StartTLSSMTP,
			smtpScript([]string{"mail.example", "STARTTLS"}, "220 go ahead\r\nINJECTED\r\n")},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv := newStartTLSServer(t, cfg, tc.script)
			opts := srv.options(tc.proto)
			opts.Roots = ca.pool

			res := runProbe(t, opts)
			if res.Success {
				t.Fatal("probe succeeded although the upgrade was not agreed")
			}
			if res.FailureReason != probe.ReasonStartTLSFailed {
				t.Errorf("reason = %q, want %q", res.FailureReason, probe.ReasonStartTLSFailed)
			}
			if d := diag(t, res); d.TLS != nil {
				t.Error("TLS diagnostics present although no handshake took place")
			}
		})
	}
}

// TestStartTLSInterrupted covers the network failures during the dialogue: they
// keep their usual reason, and a hang is attributed to the starttls phase.
func TestStartTLSInterrupted(t *testing.T) {
	t.Parallel()

	ca := newAuthority(t, "Sentinel STARTTLS Test CA")
	cfg := serverConfig(ca.issue(t, leafOptions{}))

	t.Run("server goes silent after the greeting", func(t *testing.T) {
		t.Parallel()
		srv := newStartTLSServer(t, cfg, func(r *bufio.Reader, w io.Writer) bool {
			_, _ = io.WriteString(w, "220 ready\r\n")
			readCmd(r)
			_, _ = r.ReadByte() // block until the test ends
			return false
		})
		opts := srv.options(StartTLSSMTP)
		opts.Timeout = 300 * time.Millisecond

		start := time.Now()
		res := runProbe(t, opts)
		if !res.FailureReason.IsTimeout() {
			t.Fatalf("reason = %q, want a timeout", res.FailureReason)
		}
		if res.TimeoutPhase != probe.PhaseStartTLS {
			t.Errorf("phase = %q, want starttls", res.TimeoutPhase)
		}
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Errorf("probe took %v against a 300ms timeout", elapsed)
		}
	})

	t.Run("server closes mid-dialogue", func(t *testing.T) {
		t.Parallel()
		srv := newStartTLSServer(t, cfg, func(_ *bufio.Reader, w io.Writer) bool {
			_, _ = io.WriteString(w, "220-ready\r\n")
			return false
		})
		res := runProbe(t, srv.options(StartTLSSMTP))
		if res.Success || res.FailureReason == probe.ReasonStartTLSFailed {
			t.Errorf("reason = %q, want a network-level reason", res.FailureReason)
		}
	})
}

// TestStartTLSCertificateStillChecked makes sure the upgrade path does not skip
// certificate verification: an untrusted certificate behind STARTTLS must fail
// exactly like one on a direct TLS port.
func TestStartTLSCertificateStillChecked(t *testing.T) {
	t.Parallel()

	ca := newAuthority(t, "Sentinel STARTTLS Test CA")
	srv := newStartTLSServer(t, serverConfig(ca.issue(t, leafOptions{})),
		smtpScript([]string{"mail.example", "STARTTLS"}, "220 go ahead\r\n"))

	res := runProbe(t, srv.options(StartTLSSMTP)) // system roots: the test CA is unknown
	if res.Success {
		t.Fatal("probe accepted an untrusted certificate behind STARTTLS")
	}
	if res.FailureReason != probe.ReasonCertificateInvalid {
		t.Errorf("reason = %q, want %q", res.FailureReason, probe.ReasonCertificateInvalid)
	}
}

func TestNewRejectsUnknownStartTLS(t *testing.T) {
	t.Parallel()

	_, err := New(Options{Name: "x", Host: "example.org", Port: 25, Timeout: time.Second, StartTLS: "xmpp"})
	if err == nil {
		t.Fatal("expected an error for an unsupported starttls protocol")
	}
}

func TestCollectorStartTLSDuration(t *testing.T) {
	t.Parallel()

	recs := []store.Record{
		{
			Target: "submission", Type: ProbeType,
			Result: probe.Result{Diagnostics: &Diagnostics{StartTLS: StartTLSSMTP, StartTLSDuration: 25 * time.Millisecond}},
		},
		{
			Target: "ldaps", Type: ProbeType,
			Result: probe.Result{Diagnostics: &Diagnostics{}},
		},
	}
	reg := prometheus.NewRegistry()
	reg.MustRegister(NewCollector(fakeResults{recs: recs}))

	const name = "sentinel_tls_starttls_duration_seconds"
	if v, ok := gatherValue(t, reg, name, map[string]string{"target": "submission"}); !ok || v != 0.025 {
		t.Errorf("%s = %v ok=%v, want 0.025", name, v, ok)
	}
	// A direct TLS target has no dialogue; a zero series would read as "instant".
	if _, ok := gatherValue(t, reg, name, map[string]string{"target": "ldaps"}); ok {
		t.Errorf("%s emitted for a target without starttls", name)
	}
}
