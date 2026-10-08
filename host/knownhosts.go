package host

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"strings"

	"github.com/owenthereal/upterm/utils"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

var (
	// ErrUnknownHostKey is what KnownHosts.Check reports for a key that no
	// line of the file names.
	ErrUnknownHostKey = errors.New("host key is not known")
	// ErrHostKeyChanged is what KnownHosts.Check reports for a host whose line
	// names a different key.
	ErrHostKeyChanged = errors.New("host key has changed")
)

const (
	markerCert = "@cert-authority"

	errKeyMismatch = `
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!
Someone could be eavesdropping on you right now (man-in-the-middle attack)!
It is also possible that a host key has just been changed.
The fingerprint for the %s key sent by the remote host is
%s.
Please contact your system administrator.
Add correct host key in %s to get rid of this message.
Offending %s key in %s:%d`
	errNoAuthoritiesHostname = "ssh: no authorities for hostname"
)

// noHostIP stands in for the server's address when the connection was
// tunnelled. OpenSSH prints "<no hostip for proxy command>" in the same
// situation; upterm reaches it through --proxy or the proxy environment rather
// than a ProxyCommand.
const noHostIP = "<no hostip for proxy>"

// KnownHosts is a known_hosts file and the three steps of trusting a relay's
// host key against it: Check, Confirm and Record. The callbacks that
// `upterm host` hands to its tunnel are those steps composed; a caller with no
// connection open can use them one at a time.
type KnownHosts struct {
	File string
	// Stdout takes the prompt and the "Permanently added" warning.
	Stdout io.Writer
	// Proxied suppresses the peer address in the prompt, because through a
	// tunnel it belongs to the proxy rather than to the server.
	Proxied bool
}

// hostKeyChangedError is errKeyMismatch's text, as an error that is also
// ErrHostKeyChanged.
type hostKeyChangedError string

func (e hostKeyChangedError) Error() string { return string(e) }
func (hostKeyChangedError) Unwrap() error   { return ErrHostKeyChanged }

// Check never prompts and never writes. A missing file, or a missing
// directory, is an empty trust store. It returns nil when a key line or an
// @cert-authority line trusts key, an error wrapping ErrUnknownHostKey when no
// line names it, and an error wrapping ErrHostKeyChanged when a line for
// hostname names a different key. Anything else is as knownhosts returns it.
func (k KnownHosts) Check(hostname string, remote net.Addr, key ssh.PublicKey) error {
	cb, err := knownhosts.New(k.File)
	if errors.Is(err, fs.ErrNotExist) {
		return ErrUnknownHostKey
	}
	if err != nil {
		return err
	}

	err = cb(hostname, remote, key)
	if err == nil {
		return nil
	}

	kerr, ok := err.(*knownhosts.KeyError)
	// Return err if it's neither key error or no authorities hostname error
	if !ok && !strings.HasPrefix(err.Error(), errNoAuthoritiesHostname) {
		return err
	}

	// If kerr.Want is non-empty, there was a mismatch, which can signify a MITM attack
	if kerr != nil && len(kerr.Want) != 0 {
		kk := kerr.Want[0] // TODO: take care of multiple key mismatches
		fp := utils.FingerprintSHA256(kk.Key)
		kt := keyType(kk.Key.Type())
		return hostKeyChangedError(fmt.Sprintf(errKeyMismatch, kt, fp, kk.Filename, kt, kk.Filename, kk.Line))
	}

	return ErrUnknownHostKey
}

// Confirm prints the prompt and reads the answer from in, which is "yes", the
// key's fingerprint or "no"; anything else asks again. It returns true after
// recording the key, and false for "no". It returns (false, ctx.Err()) as soon
// as ctx ends, and records nothing once it has: a ctx that is already done
// gets no prompt and no read.
//
// Each line is read a byte at a time, on a goroutine of its own, so that
// nothing typed after the answer is consumed. A read that is still blocked when
// ctx ends is abandoned rather than interrupted: a terminal read cannot be
// cancelled, and ctx ending means the process is.
func (k KnownHosts) Confirm(ctx context.Context, in io.Reader, hostname string, remote net.Addr, key ssh.PublicKey) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}

	signer := key
	if cert, ok := key.(*ssh.Certificate); ok {
		signer = cert.SignatureKey
	}

	fp := utils.FingerprintSHA256(signer)
	hostIP := knownhosts.Normalize(remote.String())
	if k.Proxied {
		hostIP = noHostIP
	}
	_, _ = fmt.Fprintf(k.Stdout, "The authenticity of host '%s (%s)' can't be established.\n", knownhosts.Normalize(hostname), hostIP)
	_, _ = fmt.Fprintf(k.Stdout, "%s key fingerprint is %s.\n", keyType(signer.Type()), fp)
	_, _ = fmt.Fprintf(k.Stdout, "Are you sure you want to continue connecting (yes/no/[fingerprint])? ")

	type reply struct {
		line string
		err  error
	}
	for {
		replies := make(chan reply, 1)
		go func() {
			line, err := readLine(in)
			replies <- reply{line, err}
		}()

		var r reply
		select {
		case r = <-replies:
		case <-ctx.Done():
			return false, ctx.Err()
		}
		// With an answer and a done ctx both ready, select may pick either.
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if r.err != nil {
			return false, fmt.Errorf("could not read host-key confirmation from stdin: %w; "+
				"to confirm the %s host key of %s, re-run interactively, "+
				"pre-populate %s with a verified host key, or use --skip-host-key-check to automatically accept new host keys",
				r.err, keyType(signer.Type()), hostname, k.File)
		}

		confirm := strings.TrimSpace(r.line)

		if confirm == "yes" || confirm == fp {
			if err := k.Record(hostname, key, false); err != nil {
				return false, err
			}
			return true, nil
		}

		if confirm == "no" {
			return false, nil
		}

		_, _ = fmt.Fprintf(k.Stdout, "Please type 'yes', 'no' or the fingerprint: ")
	}
}

// readLine reads up to and including the next newline, one byte at a time so
// that it takes nothing beyond it.
func readLine(in io.Reader) (string, error) {
	var line []byte
	b := make([]byte, 1)
	for {
		n, err := in.Read(b)
		if n == 1 {
			if b[0] == '\n' {
				return string(line), nil
			}
			line = append(line, b[0])
		}
		if err != nil {
			return string(line), err
		}
	}
}

// Record appends hostname's line to the file, first creating the file and its
// directory (0700) if they don't exist, and ending the file's last line if it
// has no newline. A certificate's signing key is recorded as an
// @cert-authority line. announce prints the "Permanently added" warning.
func (k KnownHosts) Record(hostname string, key ssh.PublicKey, announce bool) error {
	cert, isCert := key.(*ssh.Certificate)
	if isCert {
		key = cert.SignatureKey
	}

	if announce {
		_, _ = fmt.Fprintf(k.Stdout, "Warning: Permanently added '%s' (%s) to the list of known hosts.\n", knownhosts.Normalize(hostname), keyType(key.Type()))
	}

	if err := createFileIfNotExist(k.File); err != nil {
		return err
	}

	f, err := os.OpenFile(k.File, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return err
	}
	defer func() {
		_ = f.Close()
	}()

	// Only store the hostname, not the IP address.
	// This prevents breakage when server IPs change due to:
	// - Load balancers and auto-scaling
	// - Cloud redeployments
	// - CDN/proxy rotation
	// - IPv6 address rotation
	// The security benefit of storing IPs is minimal in modern infrastructure
	// since we already trust DNS, and MITM attacks would need to compromise
	// both DNS and the host key.
	addr := []string{hostname}

	line := knownhosts.Line(addr, key)

	if isCert {
		line = fmt.Sprintf("%s %s", markerCert, line)
	}

	// A last line without its newline would swallow this one, and the file
	// would no longer parse.
	unended, err := endsMidLine(f)
	if err != nil {
		return err
	}
	if unended {
		line = "\n" + line
	}

	if _, err := f.WriteString(line + "\n"); err != nil {
		return err
	}

	return nil
}

// endsMidLine reports whether f is non-empty and its last byte is not a newline.
func endsMidLine(f *os.File) (bool, error) {
	info, err := f.Stat()
	if err != nil {
		return false, err
	}
	if info.Size() == 0 {
		return false, nil
	}

	var last [1]byte
	if _, err := f.ReadAt(last[:], info.Size()-1); err != nil {
		return false, err
	}

	return last[0] != '\n', nil
}
