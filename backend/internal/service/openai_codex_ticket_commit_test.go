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

type ticketCommitScopeRepo struct {
	*codexTicketRefreshRepo
	onWrite func()
	once    sync.Once
}

func (r *ticketCommitScopeRepo) UpdateExtra(ctx context.Context, id int64, extra map[string]any) error {
	err := r.codexTicketRefreshRepo.UpdateExtra(ctx, id, extra)
	r.once.Do(r.onWrite)
	return err
}

func TestCodexTicketRequestDiscardsScopeChangeDuringPersistence(t *testing.T) {
	settingsRepo := &codexTicketSettingRepo{codexPolicyMigrationRepoStub: &codexPolicyMigrationRepoStub{values: map[string]string{SettingKeyOpenAICodexTicketAccountIDs: "[41]"}}}
	svc := ticketTestService(t, config.OpenAICodexTicketConfig{Enabled: true, HarvestProxyURL: "http://proxy:8080"}, &codexTicketFuncUpstream{do: func(*http.Request) (*http.Response, error) { return codexTicketResponse(), nil }})
	svc.settingService = NewSettingService(settingsRepo, svc.cfg)
	a := ticketTestAccount(41)
	repo := &ticketCommitScopeRepo{codexTicketRefreshRepo: &codexTicketRefreshRepo{accounts: []Account{*a}}, onWrite: func() {
		settingsRepo.values[SettingKeyOpenAICodexTicketAccountIDs] = "[42]"
		svc.settingService.InvalidateOpenAICodexTicketAccountsCache()
	}}
	svc.accountRepo = repo
	h := http.Header{}
	require.NoError(t, svc.applyOpenAICodexTicket(context.Background(), a, "gpt-6-astra", h), "取消选择后按普通账号规则转发")
	require.Empty(t, h.Get(openAICodexTurnStateHeader))
	require.Nil(t, svc.lookupOpenAICodexTicket(a, "gpt-6-astra"))
	require.Nil(t, repo.updates[openAICodexTicketExtraKey("gpt-6-astra")])
	require.False(t, svc.codexTicketCooldownActive(a))
}

func TestCodexTicketRequestDifferentAccountsRunInParallel(t *testing.T) {
	var calls atomic.Int32
	both := make(chan struct{})
	svc := ticketTestService(t, config.OpenAICodexTicketConfig{Enabled: true, HarvestProxyURL: "http://proxy:8080"}, &codexTicketFuncUpstream{do: func(req *http.Request) (*http.Response, error) {
		if calls.Add(1) == 2 {
			close(both)
		}
		select {
		case <-both:
			return codexTicketResponse(), nil
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
	}})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	errs := make(chan error, 2)
	for _, id := range []int64{41, 42} {
		go func(id int64) {
			errs <- svc.applyOpenAICodexTicket(ctx, ticketTestAccount(id), "gpt-6-astra", http.Header{})
		}(id)
	}
	require.NoError(t, <-errs)
	require.NoError(t, <-errs)
	require.Equal(t, int32(2), calls.Load())
}

func TestCodexTicketPolicySaveDoesNotCancelCurrentScope(t *testing.T) {
	ctx := context.Background()
	s := NewSettingService(nil, &config.Config{Gateway: config.GatewayConfig{OpenAICodexTicket: config.OpenAICodexTicketConfig{Enabled: true, AccountIDs: []int64{41}}}})
	_, before := s.codexTicketAccountsSnapshot(ctx)
	require.True(t, s.GetOpenAICodexTicketEnabled(ctx, true))
	s.refreshCodexTicketScopeAfterSettings(&SystemSettings{OpenAICodexTicketEnabled: true, OpenAICodexTicketAccountIDs: []int64{41}})
	_, after := s.codexTicketAccountsSnapshot(ctx)
	require.Equal(t, before, after)
	s.refreshCodexTicketScopeAfterSettings(&SystemSettings{OpenAICodexTicketEnabled: false, OpenAICodexTicketAccountIDs: []int64{41}})
	_, after = s.codexTicketAccountsSnapshot(ctx)
	require.Greater(t, after, before)
}
