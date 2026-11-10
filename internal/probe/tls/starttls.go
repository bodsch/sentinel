package tls

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// StartTLS names the plaintext protocol whose upgrade dialogue runs before the
// TLS handshake. The zero value, StartTLSNone, means the endpoint speaks TLS
// immediately on connect.
type StartTLS string

// Supported STARTTLS dialogues.
const (
	StartTLSNone StartTLS = ""
	// StartTLSSMTP is SMTP's STARTTLS (RFC 3207), typically port 587 or 25.
	StartTLSSMTP StartTLS = "smtp"
	// StartTLSIMAP is IMAP's STARTTLS (RFC 3501), typically port 143.
	StartTLSIMAP StartTLS = "imap"
	// StartTLSPOP3 is POP3's STLS (RFC 2595), typically port 110.
	StartTLSPOP3 StartTLS = "pop3"
	// StartTLSLDAP is LDAP's StartTLS extended operation (RFC 4511), typically
	// port 389.
	StartTLSLDAP StartTLS = "ldap"
)

// errStartTLS marks a dialogue the server answered, but not with an agreement
// to upgrade: a refusing greeting, a missing STARTTLS capability, a negative
// reply, or a malformed response. Network-level failures during the dialogue
// are returned unwrapped so they classify like any other connection problem.
var errStartTLS = errors.New("starttls")

const (
	// maxLineBytes bounds one line of a text protocol reply. It is also the
	// reader's buffer size, so a longer line fails instead of growing memory.
	maxLineBytes = 4096
	// maxReplyLines bounds a multi-line reply (an SMTP EHLO answer, untagged
	// IMAP responses), so a server streaming continuation lines cannot keep the
	// probe busy until the deadline.
	maxReplyLines = 64
	// maxLDAPMessageBytes bounds the LDAP extended response. A real one is a few
	// dozen bytes; the cap only exists to reject a hostile length field.
	maxLDAPMessageBytes = 16 << 10
	// ehloName is the client name sent in SMTP EHLO. A fixed name keeps the
	// probe deterministic and discloses nothing about the monitoring host.
	ehloName = "localhost"
	// imapTag is the tag of the IMAP STARTTLS command.
	imapTag = "a001"
)

// ldapStartTLSRequest is the encoded LDAPMessage
//
//	SEQUENCE { messageID 1, [APPLICATION 23] { [0] "1.3.6.1.4.1.1466.20037" } }
//
// i.e. the StartTLS extended request of RFC 4511 section 4.14.
var ldapStartTLSRequest = []byte{
	0x30, 0x1d, // LDAPMessage, 29 bytes
	0x02, 0x01, 0x01, // messageID 1
	0x77, 0x18, // [APPLICATION 23] ExtendedRequest, 24 bytes
	0x80, 0x16, // [0] requestName, 22 bytes
	'1', '.', '3', '.', '6', '.', '1', '.', '4', '.', '1', '.',
	'1', '4', '6', '6', '.', '2', '0', '0', '3', '7',
}

// upgrade runs the plaintext dialogue that asks the server to switch the
// connection to TLS. On success the next bytes on conn belong to the TLS
// handshake.
//
// Parameters:
//   - ctx: the probe context; its deadline bounds the dialogue and cancelling
//     it aborts a blocked read.
//   - conn: the freshly connected, still plaintext connection.
//   - proto: the dialogue to run; must not be StartTLSNone.
//
// It returns nil when the server agreed to upgrade, an error wrapping
// errStartTLS when it answered but did not agree, or the network error that
// interrupted the dialogue.
func upgrade(ctx context.Context, conn net.Conn, proto StartTLS) error {
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return err
		}
	}
	// A cancelled context must unblock a read waiting on a silent server.
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()

	r := bufio.NewReaderSize(conn, maxLineBytes)

	var err error
	switch proto {
	case StartTLSSMTP:
		err = upgradeSMTP(r, conn)
	case StartTLSIMAP:
		err = upgradeIMAP(r, conn)
	case StartTLSPOP3:
		err = upgradePOP3(r, conn)
	case StartTLSLDAP:
		err = upgradeLDAP(r, conn)
	default:
		return fmt.Errorf("%w: unsupported protocol %q", errStartTLS, proto)
	}
	if ctxErr := ctx.Err(); ctxErr != nil && err != nil {
		// The deadline was forced by the AfterFunc above; report the cause, not
		// the artificial deadline error it produced.
		return ctxErr
	}
	if err != nil {
		return err
	}

	// Bytes the server sent after agreeing arrived in plaintext. Handing them to
	// the TLS layer would let an on-path attacker inject data that is later
	// read as if it had been protected, so the upgrade is refused instead.
	if r.Buffered() > 0 {
		return fmt.Errorf("%w: server sent %d unexpected bytes before the TLS handshake", errStartTLS, r.Buffered())
	}
	return conn.SetDeadline(time.Time{})
}

// upgradeSMTP runs greeting → EHLO → STARTTLS (RFC 3207).
func upgradeSMTP(r *bufio.Reader, w io.Writer) error {
	if _, err := expectSMTP(r, 220, "greeting"); err != nil {
		return err
	}
	if err := writeLine(w, "EHLO "+ehloName); err != nil {
		return err
	}
	lines, err := expectSMTP(r, 250, "EHLO")
	if err != nil {
		return err
	}
	// The first line is the server's name; each further line is one extension
	// keyword followed by optional parameters.
	offered := false
	for _, l := range lines[1:] {
		if fields := strings.Fields(l); len(fields) > 0 && strings.EqualFold(fields[0], "STARTTLS") {
			offered = true
			break
		}
	}
	if !offered {
		return fmt.Errorf("%w: server does not offer STARTTLS in its EHLO reply", errStartTLS)
	}
	if err := writeLine(w, "STARTTLS"); err != nil {
		return err
	}
	_, err = expectSMTP(r, 220, "STARTTLS")
	return err
}

// expectSMTP reads one complete, possibly multi-line SMTP reply and checks its
// code.
//
// Parameters:
//   - r: the reader positioned at the start of a reply.
//   - want: the expected three-digit reply code.
//   - step: names the dialogue step in an error.
//
// It returns the text of each line (after the code and separator), or an error.
func expectSMTP(r *bufio.Reader, want int, step string) ([]string, error) {
	var texts []string
	for range maxReplyLines {
		line, err := readLine(r)
		if err != nil {
			return nil, err
		}
		if len(line) < 3 || !isDigits(line[:3]) {
			return nil, fmt.Errorf("%w: malformed SMTP %s reply %q", errStartTLS, step, truncate(line))
		}
		if code, _ := strconv.Atoi(line[:3]); code != want {
			return nil, fmt.Errorf("%w: SMTP %s answered %q, want %d", errStartTLS, step, truncate(line), want)
		}
		rest := line[3:]
		if rest == "" || rest[0] == ' ' {
			return append(texts, strings.TrimSpace(rest)), nil
		}
		if rest[0] != '-' {
			return nil, fmt.Errorf("%w: malformed SMTP %s reply %q", errStartTLS, step, truncate(line))
		}
		texts = append(texts, rest[1:])
	}
	return nil, fmt.Errorf("%w: SMTP %s reply exceeds %d lines", errStartTLS, step, maxReplyLines)
}

// upgradeIMAP runs greeting → STARTTLS (RFC 3501 section 6.2.1).
func upgradeIMAP(r *bufio.Reader, w io.Writer) error {
	greeting, err := readLine(r)
	if err != nil {
		return err
	}
	// "* PREAUTH" is a valid greeting but forbids STARTTLS; "* BYE" refuses the
	// connection. Only "* OK" leads on to an upgrade.
	if !hasPrefixFold(greeting, "* OK") {
		return fmt.Errorf("%w: IMAP greeting %q, want \"* OK\"", errStartTLS, truncate(greeting))
	}
	if err := writeLine(w, imapTag+" STARTTLS"); err != nil {
		return err
	}
	for range maxReplyLines {
		line, err := readLine(r)
		if err != nil {
			return err
		}
		if strings.HasPrefix(line, "* ") {
			continue // untagged data, e.g. a CAPABILITY announcement
		}
		if hasPrefixFold(line, imapTag+" OK") {
			return nil
		}
		return fmt.Errorf("%w: IMAP STARTTLS answered %q", errStartTLS, truncate(line))
	}
	return fmt.Errorf("%w: no tagged IMAP reply within %d lines", errStartTLS, maxReplyLines)
}

// upgradePOP3 runs greeting → STLS (RFC 2595 section 4).
func upgradePOP3(r *bufio.Reader, w io.Writer) error {
	greeting, err := readLine(r)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(greeting, "+OK") {
		return fmt.Errorf("%w: POP3 greeting %q, want \"+OK\"", errStartTLS, truncate(greeting))
	}
	if err := writeLine(w, "STLS"); err != nil {
		return err
	}
	reply, err := readLine(r)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(reply, "+OK") {
		return fmt.Errorf("%w: POP3 STLS answered %q", errStartTLS, truncate(reply))
	}
	return nil
}

// upgradeLDAP sends the StartTLS extended request and checks the extended
// response for resultCode success (RFC 4511 section 4.14).
func upgradeLDAP(r *bufio.Reader, w io.Writer) error {
	if _, err := w.Write(ldapStartTLSRequest); err != nil {
		return err
	}

	tag, msg, err := readBER(r, maxLDAPMessageBytes)
	if err != nil {
		return err
	}
	if tag != 0x30 {
		return fmt.Errorf("%w: LDAP reply is not an LDAPMessage (tag 0x%02x)", errStartTLS, tag)
	}
	body := bytes.NewReader(msg)

	tag, id, err := readBER(body, maxLDAPMessageBytes)
	if err != nil || tag != 0x02 {
		return fmt.Errorf("%w: LDAP reply has no messageID", errStartTLS)
	}
	tag, resp, err := readBER(body, maxLDAPMessageBytes)
	if err != nil {
		return fmt.Errorf("%w: truncated LDAP reply", errStartTLS)
	}
	// messageID 0 with an extended response is a Notice of Disconnection: the
	// server is closing the connection rather than answering.
	if len(id) != 1 || id[0] != 0x01 || tag != 0x78 {
		return fmt.Errorf("%w: unexpected LDAP reply (messageID % x, tag 0x%02x)", errStartTLS, id, tag)
	}

	fields := bytes.NewReader(resp)
	tag, code, err := readBER(fields, maxLDAPMessageBytes)
	if err != nil || tag != 0x0a || len(code) == 0 {
		return fmt.Errorf("%w: LDAP reply has no resultCode", errStartTLS)
	}
	if !allZero(code) {
		diag := ""
		// matchedDN, then diagnosticMessage.
		if _, _, err := readBER(fields, maxLDAPMessageBytes); err == nil {
			if t, text, err := readBER(fields, maxLDAPMessageBytes); err == nil && t == 0x04 {
				diag = string(text)
			}
		}
		return fmt.Errorf("%w: LDAP StartTLS resultCode %d %q", errStartTLS, berInt(code), truncate(diag))
	}
	return nil
}

// berReader is what readBER consumes: the connection's buffered reader or a
// bytes.Reader over an already-read element.
type berReader interface {
	io.Reader
	io.ByteReader
}

// readBER reads one BER TLV with a single-byte tag and a definite length.
//
// Lengths are accepted in short or long form with up to four length octets —
// Active Directory always uses the four-octet form — so this is deliberately
// more lenient than encoding/asn1, which insists on DER's minimal encoding.
//
// Parameters:
//   - r: the reader positioned at a tag.
//   - limit: the largest value length accepted.
//
// It returns the tag and the value bytes, or an error for an indefinite,
// oversized or truncated element.
func readBER(r berReader, limit int) (byte, []byte, error) {
	tag, err := r.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	first, err := r.ReadByte()
	if err != nil {
		return 0, nil, err
	}

	length := int(first)
	if first&0x80 != 0 {
		n := int(first & 0x7f)
		if n == 0 || n > 4 {
			return 0, nil, fmt.Errorf("%w: unsupported BER length form 0x%02x", errStartTLS, first)
		}
		length = 0
		for range n {
			b, err := r.ReadByte()
			if err != nil {
				return 0, nil, err
			}
			length = length<<8 | int(b)
		}
	}
	if length > limit {
		return 0, nil, fmt.Errorf("%w: BER element of %d bytes exceeds %d", errStartTLS, length, limit)
	}

	value := make([]byte, length)
	if _, err := io.ReadFull(r, value); err != nil {
		return 0, nil, err
	}
	return tag, value, nil
}

// goodbye sends the protocol's polite end-of-session command over the
// established TLS connection, so the server logs an orderly quit rather than a
// connection lost right after STARTTLS. It is best effort: the measurement is
// complete, and a failure here changes nothing about the result.
//
// Parameters:
//   - w: the TLS connection.
//   - proto: the dialogue that was run before the handshake.
func goodbye(w io.Writer, proto StartTLS) {
	switch proto {
	case StartTLSSMTP, StartTLSPOP3:
		_ = writeLine(w, "QUIT")
	case StartTLSIMAP:
		_ = writeLine(w, "a002 LOGOUT")
	case StartTLSLDAP:
		// UnbindRequest: SEQUENCE { messageID 2, [APPLICATION 2] NULL }.
		_, _ = w.Write([]byte{0x30, 0x05, 0x02, 0x01, 0x02, 0x42, 0x00})
	case StartTLSNone:
	}
}

// readLine reads one CRLF- or LF-terminated line without its terminator. A line
// longer than the reader's buffer fails with bufio.ErrBufferFull instead of
// growing memory.
func readLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadSlice('\n')
	if err != nil {
		if errors.Is(err, bufio.ErrBufferFull) {
			return "", fmt.Errorf("%w: reply line exceeds %d bytes", errStartTLS, maxLineBytes)
		}
		return "", err
	}
	return strings.TrimRight(string(line), "\r\n"), nil
}

// writeLine writes s followed by CRLF.
func writeLine(w io.Writer, s string) error {
	_, err := io.WriteString(w, s+"\r\n")
	return err
}

// truncate shortens a server-supplied string for an error message, so a hostile
// reply cannot bloat the log line.
func truncate(s string) string {
	const limit = 120
	if len(s) <= limit {
		return s
	}
	return s[:limit] + "…"
}

// hasPrefixFold reports whether s begins with prefix, ignoring ASCII case.
func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}

// isDigits reports whether s consists of ASCII digits only.
func isDigits(s string) bool {
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

// allZero reports whether every byte of b is zero, i.e. a BER integer of value 0.
func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// berInt decodes a short, non-negative BER integer for an error message.
func berInt(b []byte) int {
	n := 0
	for _, c := range b {
		n = n<<8 | int(c)
	}
	return n
}
