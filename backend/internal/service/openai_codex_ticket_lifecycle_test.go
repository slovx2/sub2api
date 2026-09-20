package service

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/stretchr/testify/require"
)

type codexTicketFuncUpstream struct {
	HTTPUpstream
	do func(*http.Request) (*http.Response, error)
}

func (u *codexTicketFuncUpstream) Do(req *http.Request, _ string, _ int64, _ int) (*http.Response, error) {
	return u.do(req)
}
func codexTicketResponse() *http.Response {
	h := http.Header{}
	h.Set(openAICodexTurnStateHeader, fakeCodexTicketState(292))
	return &http.Response{StatusCode: http.StatusOK, Header: h, Body: io.NopCloser(strings.NewReader("data: {}\n\n"))}
}

func TestCodexTicketProbeBypassesPluginDuringWiring(t *testing.T) {
	manager := &PluginManager{}
	manager.route.Store(&pluginRoute{pluginID: 1, rolloutPercent: 100, unavailable: "plugin must not handle synthetic probes"})
	var calls atomic.Int64
	upstream := &codexTicketFuncUpstream{do: func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		if HTTPUpstreamProfileFromContext(req.Context()) != HTTPUpstreamProfileOpenAIHarvest || !req.Close {
			return nil, errors.New("missing no-reuse transport profile")
		}
		return codexTicketResponse(), nil
	}}
	svc := ticketTestService(t, config.OpenAICodexTicketConfig{Enabled: true}, upstream)
	svc.SetPluginManager(manager)
	account := ticketTestAccount(41)
	// This binding rejects ordinary traffic; harvesting still uses the dedicated transport.
	request, _ := http.NewRequest(http.MethodPost, "https://example.com", nil)
	_, err := svc.doOpenAIUpstream(request, "", account)
	require.Error(t, err)
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 200; i++ {
			svc.SetPluginManager(manager)
		}
	}()
	close(start)
	for i := 0; i < 20; i++ {
		state, status, err := svc.fireOpenAICodexTicketProbe(context.Background(), account, "test-token", "gpt-6-astra", "http://proxy.example.com:8080", time.Second)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, status)
		require.Len(t, state, 292)
	}
	wg.Wait()
	require.Equal(t, int64(20), calls.Load())
}

type codexTicketHeaderOnlyBody struct{ reads, closes int }

func (b *codexTicketHeaderOnlyBody) Read([]byte) (int, error) { b.reads++; return 0, io.EOF }
func (b *codexTicketHeaderOnlyBody) Close() error             { b.closes++; return nil }
func TestCodexTicketProbeClosesStreamWithoutDraining(t *testing.T) {
	body := &codexTicketHeaderOnlyBody{}
	svc := ticketTestService(t, config.OpenAICodexTicketConfig{}, &codexTicketFuncUpstream{do: func(*http.Request) (*http.Response, error) {
		response := codexTicketResponse()
		response.Body = body
		return response, nil
	}})
	_, _, err := svc.fireOpenAICodexTicketProbe(context.Background(), ticketTestAccount(41), "test-token", "gpt-6-astra", "", time.Second)
	require.NoError(t, err)
	require.Zero(t, body.reads)
	require.Equal(t, 1, body.closes)
}

func TestCodexTicketPolicyExemptsCredentialShadows(t *testing.T) {
	parentID := int64(41)
	parent := ticketTestAccount(parentID)
	shadow := ticketTestAccount(42)
	shadow.ParentAccountID = &parentID
	shadow.Status = StatusActive
	cfg := config.OpenAICodexTicketConfig{Enabled: true, HarvestProxyURL: "http://proxy.example.com:8080"}
	upstream := &httpUpstreamRecorder{}
	svc := ticketTestService(t, cfg, upstream)
	svc.accountRepo = &codexTicketRefreshRepo{accounts: []Account{*shadow}}
	require.False(t, svc.codexTicketErrorActive(parent))
	for _, accountType := range []string{AccountTypeOAuth, AccountTypeSetupToken} {
		shadow.Type = accountType
		require.False(t, svc.codexTicketErrorActive(shadow))
		headers := http.Header{}
		headers.Set(openAICodexTurnStateHeader, "client-state")
		require.NoError(t, svc.applyOpenAICodexTicket(context.Background(), shadow, "gpt-6-astra", headers))
		require.Equal(t, "client-state", headers.Get(openAICodexTurnStateHeader))
		require.Empty(t, OpenAICodexTicketStatuses(shadow, cfg, time.Now()))
		svc.probeCodexTicketForTest(context.Background(), shadow, "gpt-6-astra")
	}
	requestTicket(t, svc, shadow, "gpt-6-astra")
	require.Empty(t, upstream.requests)
}
