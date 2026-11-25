//go:build unit

package service

import (
	"context"
	"errors"
	"net"
	"os"
	"syscall"
	"testing"
)

func TestClassifyUpstreamTransportError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want upstreamTransportErrorClass
	}{
		{"socks5 proxy credential rejected", errors.New(`Post "https://chatgpt.com/backend-api/codex/responses": socks connect tcp 85.255.176.68:12324->chatgpt.com:443: username/password authentication failed`), upstreamTransportProxyAuth},
		{"HTTP proxy 407", errors.New("Proxy Authentication Required"), upstreamTransportProxyAuth},
		{"ambiguous authentication text", errors.New("TLS client authentication failed"), upstreamTransportTransient},
		{"proxy connection refused", errors.New(`proxyconnect tcp: dial tcp 1.2.3.4:1080: connect: connection refused`), upstreamTransportNetwork},
		{"no route to host", errors.New(`dial tcp 1.2.3.4:443: connect: no route to host`), upstreamTransportNetwork},
		{"dns resolution failure", errors.New(`dial tcp: lookup proxy.example.com: no such host`), upstreamTransportNetwork},
		{"network unreachable", errors.New(`dial tcp 1.2.3.4:443: connect: network is unreachable`), upstreamTransportNetwork},

		{"client timeout", errors.New(`Post "https://chatgpt.com/...": context deadline exceeded (Client.Timeout exceeded while awaiting headers)`), upstreamTransportTransient},
		{"i/o timeout", errors.New(`dial tcp 1.2.3.4:443: i/o timeout`), upstreamTransportTransient},
		{"connection reset by peer", errors.New(`read tcp 10.0.0.1:5->2.2.2.2:443: read: connection reset by peer`), upstreamTransportTransient},
		{"unexpected eof", errors.New(`unexpected EOF`), upstreamTransportTransient},
		{"broken pipe", errors.New(`write tcp 10.0.0.1:5->2.2.2.2:443: write: broken pipe`), upstreamTransportTransient},
		{"nil error", nil, upstreamTransportTransient},

		// ── Typed-error cases ──────────────────────────────────────────────
		// ECONNREFUSED wrapped in the canonical net.OpError shape Go produces.
		{
			"ECONNREFUSED via net.OpError",
			&net.OpError{
				Op:  "dial",
				Net: "tcp",
				Err: &os.SyscallError{Syscall: "connect", Err: syscall.ECONNREFUSED},
			},
			upstreamTransportNetwork,
		},
		// Bare syscall error (errors.Is traverses the chain).
		{"ECONNREFUSED bare", syscall.ECONNREFUSED, upstreamTransportNetwork},
		{"EHOSTUNREACH bare", syscall.EHOSTUNREACH, upstreamTransportNetwork},
		{"ENETUNREACH bare", syscall.ENETUNREACH, upstreamTransportNetwork},

		{
			"DNS not found (IsNotFound=true)",
			&net.DNSError{Err: "no such host", Name: "proxy.example.com", IsNotFound: true},
			upstreamTransportNetwork,
		},
		{
			"DNS timeout",
			&net.DNSError{Err: "i/o timeout", Name: "proxy.example.com", IsTimeout: true},
			upstreamTransportNetwork,
		},
		{"context.Canceled", context.Canceled, upstreamTransportTransient},
		{"context.DeadlineExceeded", context.DeadlineExceeded, upstreamTransportTransient},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyUpstreamTransportError(tc.err)
			if got != tc.want {
				t.Fatalf("classifyUpstreamTransportError(%q) = %v, want %v", errString(tc.err), got, tc.want)
			}
		})
	}
}

func errString(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}
