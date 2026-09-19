package service

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/stretchr/testify/require"
)

type ticketHandshakeDialer struct {
	mu      sync.Mutex
	headers []http.Header
}

func (d *ticketHandshakeDialer) Dial(_ context.Context, _ string, headers http.Header, _ string) (openAIWSClientConn, int, http.Header, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.headers = append(d.headers, headers.Clone())
	return &openAIWSFakeConn{}, http.StatusSwitchingProtocols, nil, nil
}

func TestCodexTicketWSChecksOnlyOnDialAndReconnect(t *testing.T) {
	var calls atomic.Int32
	svc := ticketTestService(t, config.OpenAICodexTicketConfig{Enabled: true, HarvestProxyURL: "http://proxy:8080"}, &codexTicketFuncUpstream{do: func(*http.Request) (*http.Response, error) { calls.Add(1); return codexTicketResponse(), nil }})
	svc.cfg.Gateway.OpenAIWS.MaxConnsPerAccount = 2
	svc.cfg.Gateway.OpenAIWS.MaxIdlePerAccount = 2
	pool := newOpenAIWSConnPool(svc.cfg)
	defer pool.Close()
	dialer := &ticketHandshakeDialer{}
	pool.setClientDialerForTest(dialer)
	a := ticketTestAccount(41)
	a.Concurrency = 2
	req := openAIWSAcquireRequest{Account: a, WSURL: "wss://example.com/responses", Headers: http.Header{}, DisablePrewarm: true,
		HeadersFactory: func(ctx context.Context, h http.Header) (http.Header, error) {
			return h, svc.applyOpenAICodexTicket(ctx, a, "gpt-6-astra", h)
		}}
	first, err := pool.Acquire(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, int32(1), calls.Load())
	require.Len(t, dialer.headers[0].Get(openAICodexTurnStateHeader), 292)
	id := first.ConnID()
	first.Release()
	// 已有连接继续使用；即使缓存过期，复用连接不会重新采票。
	svc.openaiCodexTickets.Delete(openAICodexTicketKey(a.ID, "gpt-6-astra"))
	second, err := pool.Acquire(context.Background(), req)
	require.NoError(t, err)
	require.True(t, second.Reused())
	require.Equal(t, id, second.ConnID())
	require.Equal(t, int32(1), calls.Load())
	second.MarkBroken()
	second.Release()
	third, err := pool.Acquire(context.Background(), req)
	require.NoError(t, err)
	require.False(t, third.Reused())
	require.Equal(t, int32(2), calls.Load())
	third.Release()
}

func TestCodexTicketWSBackgroundDialNeverHarvests(t *testing.T) {
	var calls atomic.Int32
	svc := ticketTestService(t, config.OpenAICodexTicketConfig{Enabled: true, HarvestProxyURL: "http://proxy:8080"}, &codexTicketFuncUpstream{do: func(*http.Request) (*http.Response, error) { calls.Add(1); return codexTicketResponse(), nil }})
	ctx := context.WithValue(context.Background(), openAIWSBackgroundDialKey{}, true)
	require.Error(t, svc.applyOpenAICodexTicket(ctx, ticketTestAccount(41), "gpt-6-astra", http.Header{}))
	require.Zero(t, calls.Load())
	require.False(t, svc.codexTicketCooldownActive(ticketTestAccount(41)))
}

func TestCodexTicketHTTPOverWSNewTicketRequiresNewHandshake(t *testing.T) {
	cfg := &config.Config{}
	cfg.Gateway.OpenAIWS.MaxConnsPerAccount = 2
	cfg.Gateway.OpenAIWS.MaxIdlePerAccount = 2
	pool := newOpenAIWSConnPool(cfg)
	defer pool.Close()
	dialer := &ticketHandshakeDialer{}
	pool.setClientDialerForTest(dialer)
	a := ticketTestAccount(41)
	a.Concurrency = 2
	req := openAIWSAcquireRequest{Account: a, WSURL: "wss://example.com/responses", Headers: http.Header{}, DisablePrewarm: true}
	req.Headers.Set(openAICodexTurnStateHeader, fakeCodexTicketState(292))
	first, err := pool.Acquire(context.Background(), req)
	require.NoError(t, err)
	id := first.ConnID()
	first.Release()
	second, err := pool.Acquire(context.Background(), req)
	require.NoError(t, err)
	require.True(t, second.Reused())
	second.Release()
	req.Headers.Set(openAICodexTurnStateHeader, fakeCodexTicketState(332))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	third, err := pool.Acquire(ctx, req)
	require.NoError(t, err)
	defer third.Release()
	require.NotEqual(t, id, third.ConnID())
	require.False(t, third.Reused())
	require.Len(t, dialer.headers[1].Get(openAICodexTurnStateHeader), 332)
}
