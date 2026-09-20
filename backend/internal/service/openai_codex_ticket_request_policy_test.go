package service

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/stretchr/testify/require"
)

func setTicketPolicyForTest(s *OpenAIGatewayService, policy CodexTicketPolicy) {
	if s.settingService == nil {
		s.settingService = NewSettingService(nil, s.cfg)
	}
	s.settingService.openAICodexTicketPolicyMu.Lock()
	defer s.settingService.openAICodexTicketPolicyMu.Unlock()
	s.settingService.openAICodexTicketPolicy = &cachedCodexTicketPolicy{value: policy, expiresAt: time.Now().Add(time.Hour)}
}

func TestCodexTicketRequestRefreshBoundaries(t *testing.T) {
	now := time.Now()
	ticket := &openAICodexTicket{ExpiresAt: now.Add(600 * time.Second)}
	require.False(t, ticket.needsRefresh(now, 600*time.Second), "恰好等于提前量时不刷新")
	require.True(t, ticket.needsRefresh(now.Add(time.Nanosecond), 600*time.Second))
	require.False(t, ticket.needsRefresh(now, 0))
	require.True(t, ticket.needsRefresh(ticket.ExpiresAt, 0))
	for _, remaining := range []time.Duration{-time.Second, 0, 5 * time.Minute, time.Hour} {
		t.Run(remaining.String(), func(t *testing.T) {
			var calls atomic.Int32
			upstream := &codexTicketFuncUpstream{do: func(*http.Request) (*http.Response, error) { calls.Add(1); return codexTicketResponse(), nil }}
			svc := ticketTestService(t, config.OpenAICodexTicketConfig{Enabled: true, HarvestProxyURL: "http://proxy:8080"}, upstream)
			a := ticketTestAccount(41)
			svc.storeOpenAICodexTicket(context.Background(), a, &openAICodexTicket{Model: "gpt-6-astra", State: fakeCodexTicketState(332), Length: 332, ExpiresAt: time.Now().Add(remaining)})
			require.NoError(t, harvestTicketForTest(svc, context.Background(), a, "gpt-6-astra"))
			h := requestTicket(t, svc, a, "gpt-6-astra")
			if remaining == time.Hour {
				require.Zero(t, calls.Load())
				require.Len(t, h.Get(openAICodexTurnStateHeader), 332)
			} else {
				require.Equal(t, int32(1), calls.Load())
				require.Len(t, h.Get(openAICodexTurnStateHeader), 292)
			}
		})
	}
}

func TestCodexTicketRequestsCancelAllAndShutdown(t *testing.T) {
	for _, shutdown := range []bool{false, true} {
		t.Run(map[bool]string{true: "shutdown", false: "all_cancelled"}[shutdown], func(t *testing.T) {
			started, cancelled := make(chan struct{}), make(chan struct{})
			var calls atomic.Int32
			upstream := &codexTicketFuncUpstream{do: func(req *http.Request) (*http.Response, error) {
				calls.Add(1)
				close(started)
				<-req.Context().Done()
				close(cancelled)
				return nil, req.Context().Err()
			}}
			svc := ticketTestService(t, config.OpenAICodexTicketConfig{Enabled: true, HarvestProxyURL: "http://proxy:8080"}, upstream)
			a := ticketTestAccount(41)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- harvestTicketForTest(svc, ctx, a, "gpt-6-astra") }()
			<-started
			if shutdown {
				svc.StopOpenAICodexTicketRequests()
			} else {
				cancel()
			}
			require.Error(t, <-done)
			select {
			case <-cancelled:
			case <-time.After(time.Second):
				t.Fatal("采票未被取消")
			}
			svc.StopOpenAICodexTicketRequests()
			require.False(t, svc.codexTicketErrorActive(a))
			require.Nil(t, svc.lookupOpenAICodexTicket(a, "gpt-6-astra"))
			require.Equal(t, int32(1), calls.Load())
		})
	}
}

func TestCodexTicketRequestsPolicySnapshotAndNoIdleHarvest(t *testing.T) {
	started, finish := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	upstream := &codexTicketFuncUpstream{do: func(req *http.Request) (*http.Response, error) {
		n := calls.Add(1)
		if n == 1 {
			close(started)
			select {
			case <-finish:
			case <-req.Context().Done():
				return nil, req.Context().Err()
			}
		}
		return codexTicketResponse(), nil
	}}
	svc := ticketTestService(t, config.OpenAICodexTicketConfig{Enabled: true, HarvestProxyURL: "http://proxy:8080"}, upstream)
	setTicketPolicyForTest(svc, CodexTicketPolicy{7200, 600, 3, 1800})
	a := ticketTestAccount(41)
	svc.accountRepo = &codexTicketRefreshRepo{accounts: []Account{*a, *ticketTestAccount(42)}}
	_, err := svc.CodexTicketOverview(context.Background(), 1, 12, false)
	require.NoError(t, err)
	require.Zero(t, calls.Load(), "打开总览不会采票")
	done := make(chan error, 1)
	go func() { done <- harvestTicketForTest(svc, context.Background(), a, "gpt-6-astra") }()
	<-started
	setTicketPolicyForTest(svc, CodexTicketPolicy{3600, 0, 1, 60})
	close(finish)
	require.NoError(t, <-done)
	ticket := svc.lookupOpenAICodexTicket(a, "gpt-6-astra")
	require.Equal(t, 1, ticket.Attempts)
	require.Equal(t, 2*time.Hour, ticket.ExpiresAt.Sub(ticket.CapturedAt))
	require.NoError(t, harvestTicketForTest(svc, context.Background(), ticketTestAccount(42), "gpt-6-astra"))
	other := svc.lookupOpenAICodexTicket(ticketTestAccount(42), "gpt-6-astra")
	require.Equal(t, time.Hour, other.ExpiresAt.Sub(other.CapturedAt))
	svc.StopOpenAICodexTicketRequests()
	require.Equal(t, int32(2), calls.Load())
}

func TestCodexTicketRequestsAccountDisabledOrDeletedDuringProbe(t *testing.T) {
	for _, deleted := range []bool{false, true} {
		a := ticketTestAccount(41)
		repo := &codexTicketRefreshRepo{accounts: []Account{*a}}
		upstream := &codexTicketFuncUpstream{do: func(*http.Request) (*http.Response, error) {
			repo.mu.Lock()
			if deleted {
				repo.accounts = nil
			} else {
				repo.accounts[0].Status = "disabled"
			}
			repo.mu.Unlock()
			return codexTicketResponse(), nil
		}}
		svc := ticketTestService(t, config.OpenAICodexTicketConfig{Enabled: true, HarvestProxyURL: "http://proxy:8080"}, upstream)
		svc.accountRepo = repo
		require.Error(t, harvestTicketForTest(svc, context.Background(), a, "gpt-6-astra"))
		require.Nil(t, svc.lookupOpenAICodexTicket(a, "gpt-6-astra"))
		require.False(t, svc.codexTicketErrorActive(a))
	}
}

type failedTicketErrorRepo struct{ *codexTicketRefreshRepo }

func (r *failedTicketErrorRepo) SetError(context.Context, int64, string) error {
	return errors.New("db unavailable")
}

func TestCodexTicketErrorWriteFailureAndRecovery(t *testing.T) {
	a := ticketTestAccount(41)
	svc := ticketTestService(t, config.OpenAICodexTicketConfig{Enabled: true, HarvestProxyURL: "http://proxy:8080"}, &codexTicketFuncUpstream{do: func(*http.Request) (*http.Response, error) { return nil, errors.New("failed") }})
	svc.accountRepo = &failedTicketErrorRepo{&codexTicketRefreshRepo{accounts: []Account{*a}}}
	logs := &ticketLogMemoryRepo{}
	svc.codexTicketLogRepo = logs
	setTicketPolicyForTest(svc, CodexTicketPolicy{3600, 600, 20, 1})
	require.Error(t, harvestTicketForTest(svc, context.Background(), a, "gpt-6-astra"))
	require.True(t, svc.isOpenAIAccountRequestRuntimeBlocked(a, "other-model", false))
	page, _ := logs.List(context.Background(), CodexTicketLogFilter{})
	require.Len(t, page.Items, 2)
	require.Equal(t, "error_persist_failed", page.Items[1].Reason)
	svc.retryCodexTicketErrors(context.Background())
	page, _ = logs.List(context.Background(), CodexTicketLogFilter{})
	require.Len(t, page.Items, 3)
	require.Equal(t, "account_error_write_failed", page.Items[2].Kind)
	require.NoError(t, svc.RecoverCodexTicketAccount(context.Background(), a.ID))
	require.False(t, svc.codexTicketErrorActive(a))
	current, err := svc.accountRepo.GetByID(context.Background(), a.ID)
	require.NoError(t, err)
	require.False(t, current.Schedulable)
}
