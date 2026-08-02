package dns

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	dnslib "github.com/miekg/dns"

	"bodsch.me/sentinel/internal/probe"
)

// startTestDNSBoth starts UDP and TCP servers on the same address with the same
// handler, so a truncated-UDP / full-TCP scenario can be exercised.
func startTestDNSBoth(t *testing.T, handler dnslib.HandlerFunc) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	addr := pc.LocalAddr().String()
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	udpSrv := &dnslib.Server{PacketConn: pc, Handler: handler}
	tcpSrv := &dnslib.Server{Listener: l, Handler: handler}
	udpUp, tcpUp := make(chan struct{}), make(chan struct{})
	udpSrv.NotifyStartedFunc = func() { close(udpUp) }
	tcpSrv.NotifyStartedFunc = func() { close(tcpUp) }
	go func() { _ = udpSrv.ActivateAndServe() }()
	go func() { _ = tcpSrv.ActivateAndServe() }()
	<-udpUp
	<-tcpUp
	t.Cleanup(func() { _ = udpSrv.Shutdown(); _ = tcpSrv.Shutdown() })
	return addr
}

// startTestDNS starts a local UDP DNS server with the given handler and returns
// its address ("127.0.0.1:port"). It is torn down at test end.
func startTestDNS(t *testing.T, handler dnslib.HandlerFunc) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &dnslib.Server{PacketConn: pc, Handler: handler}
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go func() { _ = srv.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

// answerHandler replies to the question with the given resource records built
// from zone-file lines (relative to the question name).
func answerHandler(t *testing.T, rrLines ...string) dnslib.HandlerFunc {
	return func(w dnslib.ResponseWriter, r *dnslib.Msg) {
		m := new(dnslib.Msg)
		m.SetReply(r)
		for _, line := range rrLines {
			rr, err := dnslib.NewRR(line)
			if err != nil {
				t.Errorf("bad RR %q: %v", line, err)
				continue
			}
			m.Answer = append(m.Answer, rr)
		}
		_ = w.WriteMsg(m)
	}
}

func opts(server, query, typ string, expected ...string) Options {
	return Options{Name: "t", Server: server, Query: query, Type: typ, Expected: expected, Timeout: 3 * time.Second}
}

func run(t *testing.T, o Options) probe.Result {
	t.Helper()
	p, err := New(o)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p.Probe(context.Background())
}

func diag(t *testing.T, res probe.Result) *Diagnostics {
	t.Helper()
	d, ok := res.Diagnostics.(*Diagnostics)
	if !ok {
		t.Fatalf("diagnostics type = %T, want *Diagnostics", res.Diagnostics)
	}
	return d
}

func TestProbeSuccessA(t *testing.T) {
	t.Parallel()
	addr := startTestDNS(t, answerHandler(t, "example.org. 60 IN A 1.2.3.4"))

	res := run(t, opts(addr, "example.org", "A", "1.2.3.4"))
	if !res.Success {
		t.Fatalf("expected success, got %q", res.FailureReason)
	}
	d := diag(t, res)
	if d.ResponseCode != 0 || d.ResponseCodeText != "NOERROR" {
		t.Errorf("rcode = %d %q, want 0 NOERROR", d.ResponseCode, d.ResponseCodeText)
	}
	if d.AnswerCount != 1 || len(d.Answers) != 1 || d.Answers[0] != "1.2.3.4" {
		t.Errorf("answers = %v (count %d), want [1.2.3.4]", d.Answers, d.AnswerCount)
	}
	if res.Timings.DNS <= 0 {
		t.Error("expected a positive DNS timing")
	}
}

func TestProbeNXDOMAIN(t *testing.T) {
	t.Parallel()
	addr := startTestDNS(t, func(w dnslib.ResponseWriter, r *dnslib.Msg) {
		m := new(dnslib.Msg)
		m.SetRcode(r, dnslib.RcodeNameError)
		_ = w.WriteMsg(m)
	})

	res := run(t, opts(addr, "nope.example", "A"))
	if res.FailureReason != probe.ReasonDNSError {
		t.Fatalf("reason = %q, want dns_error", res.FailureReason)
	}
	if d := diag(t, res); d.ResponseCode != dnslib.RcodeNameError || d.ResponseCodeText != "NXDOMAIN" {
		t.Errorf("rcode = %d %q, want %d NXDOMAIN", d.ResponseCode, d.ResponseCodeText, dnslib.RcodeNameError)
	}
}

func TestProbeExpectedMismatch(t *testing.T) {
	t.Parallel()
	addr := startTestDNS(t, answerHandler(t, "example.org. 60 IN A 1.2.3.4"))

	res := run(t, opts(addr, "example.org", "A", "9.9.9.9"))
	if res.FailureReason != probe.ReasonValidationFailed {
		t.Fatalf("reason = %q, want validation_failed", res.FailureReason)
	}
}

func TestProbeNoExpectedSucceeds(t *testing.T) {
	t.Parallel()
	addr := startTestDNS(t, answerHandler(t, "example.org. 60 IN A 1.2.3.4"))

	if res := run(t, opts(addr, "example.org", "A")); !res.Success {
		t.Fatalf("expected success without expected values, got %q", res.FailureReason)
	}
}

func TestProbeMX(t *testing.T) {
	t.Parallel()
	addr := startTestDNS(t, answerHandler(t, "example.org. 60 IN MX 10 mail.example.org."))

	res := run(t, opts(addr, "example.org", "MX", "mail.example.org"))
	if !res.Success {
		t.Fatalf("expected success, got %q", res.FailureReason)
	}
	if d := diag(t, res); len(d.Answers) != 1 || d.Answers[0] != "mail.example.org" {
		t.Errorf("MX answers = %v, want [mail.example.org]", d.Answers)
	}
}

func TestProbeTXT(t *testing.T) {
	t.Parallel()
	addr := startTestDNS(t, answerHandler(t, `example.org. 60 IN TXT "v=spf1 -all"`))

	res := run(t, opts(addr, "example.org", "TXT", "v=spf1 -all"))
	if !res.Success {
		t.Fatalf("expected success, got %q; answers=%v", res.FailureReason, diag(t, res).Answers)
	}
}

func TestProbeTimeout(t *testing.T) {
	t.Parallel()
	// Handler never replies.
	addr := startTestDNS(t, func(dnslib.ResponseWriter, *dnslib.Msg) {})

	o := opts(addr, "example.org", "A")
	o.Timeout = 200 * time.Millisecond
	res := run(t, o)
	if res.FailureReason != probe.ReasonTimeout {
		t.Fatalf("reason = %q, want timeout", res.FailureReason)
	}
}

func TestWithDefaultPort(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"1.1.1.1":         "1.1.1.1:53",
		"1.1.1.1:5353":    "1.1.1.1:5353",
		"dns.example.org": "dns.example.org:53",
		"2001:db8::1":     "[2001:db8::1]:53",
	}
	for in, want := range cases {
		if got := withDefaultPort(in); got != want {
			t.Errorf("withDefaultPort(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestProbeTruncationFallsBackToTCP(t *testing.T) {
	t.Parallel()
	// UDP truncates to 3 answers with TC set; TCP serves the full 40.
	handler := func(w dnslib.ResponseWriter, r *dnslib.Msg) {
		m := new(dnslib.Msg)
		m.SetReply(r)
		for i := 0; i < 40; i++ {
			rr, err := dnslib.NewRR(fmt.Sprintf("example.org. 60 IN A 10.0.0.%d", i))
			if err != nil {
				t.Errorf("bad RR: %v", err)
				return
			}
			m.Answer = append(m.Answer, rr)
		}
		if w.RemoteAddr().Network() == "udp" {
			m.Truncated = true
			m.Answer = m.Answer[:3]
		}
		_ = w.WriteMsg(m)
	}
	addr := startTestDNSBoth(t, handler)

	// 10.0.0.39 is only in the full (TCP) answer set, not the truncated UDP one.
	res := run(t, opts(addr, "example.org", "A", "10.0.0.39"))
	if !res.Success {
		t.Fatalf("expected success via TCP fallback, got %q", res.FailureReason)
	}
	if d := diag(t, res); d.AnswerCount != 40 {
		t.Errorf("answer_count = %d, want 40 (full set retrieved over TCP)", d.AnswerCount)
	}
}

func TestProbeMXCaseInsensitive(t *testing.T) {
	t.Parallel()
	addr := startTestDNS(t, answerHandler(t, "example.org. 60 IN MX 10 Mail.Example.ORG."))

	// DNS names are case-insensitive: mixed-case answer must match lowercase expected.
	if res := run(t, opts(addr, "example.org", "MX", "mail.example.org")); !res.Success {
		t.Fatalf("MX case-insensitive match failed: %q", res.FailureReason)
	}
}

func TestProbeAAAAEquivalentForms(t *testing.T) {
	t.Parallel()
	addr := startTestDNS(t, answerHandler(t, "example.org. 60 IN AAAA 2001:db8::1"))

	for _, expected := range []string{"2001:DB8::1", "2001:db8:0:0:0:0:0:1"} {
		if res := run(t, opts(addr, "example.org", "AAAA", expected)); !res.Success {
			t.Errorf("AAAA expected %q did not match canonical answer: %q", expected, res.FailureReason)
		}
	}
}

func TestType(t *testing.T) {
	t.Parallel()
	p, _ := New(opts("1.1.1.1", "example.org", "A"))
	if p.Type() != ProbeType {
		t.Errorf("Type() = %q, want %q", p.Type(), ProbeType)
	}
}
