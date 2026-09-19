package service

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/stretchr/testify/require"
)

func TestCodexTicketAccountSelectionGatesAndInjects(t *testing.T) {
	ctx := context.Background()
	for _, ids := range [][]int64{nil, {}, {41}, {42}, {99999}} {
		svc := ticketTestService(t, config.OpenAICodexTicketConfig{Enabled: true, AccountIDs: ids}, nil)
		account := ticketTestAccount(41)
		selected := len(ids) == 0 || ids[0] == 41
		require.False(t, svc.codexTicketCooldownActive(account))
		headers := http.Header{openAICodexTurnStateHeader: []string{"client-state"}}
		err := svc.applyOpenAICodexTicket(ctx, account, "gpt-6-astra", headers)
		if selected {
			require.ErrorIs(t, err, ErrOpenAICodexTicketUnavailable)
		} else {
			require.NoError(t, err)
		}
		svc.ClearAccountSchedulingBlock(account.ID)
		svc.storeOpenAICodexTicket(ctx, account, &openAICodexTicket{Model: "gpt-6-astra", State: fakeCodexTicketState(292), Length: 292, ExpiresAt: time.Now().Add(time.Hour)})
		headers = http.Header{}
		headers.Set(openAICodexTurnStateHeader, "client-state")
		require.NoError(t, svc.applyOpenAICodexTicket(ctx, account, "gpt-6-astra", headers))
		if selected {
			require.Equal(t, fakeCodexTicketState(292), headers.Get(openAICodexTurnStateHeader))
		} else {
			require.Equal(t, "client-state", headers.Get(openAICodexTurnStateHeader))
		}
		require.Equal(t, selected, len(OpenAICodexTicketStatuses(account, svc.openAICodexTicketConfig(), time.Now())) > 0)
	}
}

func TestCodexTicketAccountSelectionHarvestOnlySelected(t *testing.T) {
	var calls int
	upstream := &codexTicketFuncUpstream{do: func(*http.Request) (*http.Response, error) { calls++; return codexTicketResponse(), nil }}
	svc := ticketTestService(t, config.OpenAICodexTicketConfig{Enabled: true, AccountIDs: []int64{41}, Models: []string{"gpt-6-astra"}, HarvestProxyURL: "http://proxy:8080"}, upstream)
	a, b := ticketTestAccount(41), ticketTestAccount(42)
	a.Status, b.Status = StatusActive, StatusActive
	svc.accountRepo = &codexTicketRefreshRepo{accounts: []Account{*a, *b}}
	requestTicket(t, svc, a, "gpt-6-astra")
	requestTicket(t, svc, b, "gpt-6-astra")
	require.Equal(t, 1, calls)
	require.NotNil(t, svc.lookupOpenAICodexTicket(a, "gpt-6-astra"))
	require.Nil(t, svc.lookupOpenAICodexTicket(b, "gpt-6-astra"))
}

func TestCodexTicketAccountSelectionDiscardsInflightResult(t *testing.T) {
	repo := &codexTicketSettingRepo{codexPolicyMigrationRepoStub: &codexPolicyMigrationRepoStub{values: map[string]string{SettingKeyOpenAICodexTicketAccountIDs: "[41]"}}}
	settings := NewSettingService(repo, &config.Config{})
	started, finish, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	upstream := &codexTicketFuncUpstream{do: func(*http.Request) (*http.Response, error) {
		close(started)
		<-finish
		return codexTicketResponse(), nil
	}}
	svc := ticketTestService(t, config.OpenAICodexTicketConfig{Enabled: true, HarvestProxyURL: "http://proxy:8080"}, upstream)
	svc.settingService = settings
	logs := &ticketLogMemoryRepo{}
	svc.codexTicketLogRepo = logs
	account := ticketTestAccount(41)
	go func() {
		defer close(done)
		svc.probeCodexTicketForTest(context.Background(), account, "gpt-6-astra")
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("probe did not start")
	}
	repo.values[SettingKeyOpenAICodexTicketAccountIDs] = "[42]"
	settings.InvalidateOpenAICodexTicketAccountsCache()
	close(finish)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("probe did not finish")
	}
	require.Nil(t, svc.lookupOpenAICodexTicket(account, "gpt-6-astra"))
	require.False(t, svc.codexTicketCooldownActive(account))
	require.Len(t, logs.items, 1)
	require.False(t, logs.items[0].Success)
	require.Equal(t, "scope_changed_or_cancelled", logs.items[0].Reason)
}

func TestCodexTicketAccountSelectionReloadAndErrors(t *testing.T) {
	ctx := context.Background()
	repo := &codexTicketSettingRepo{codexPolicyMigrationRepoStub: &codexPolicyMigrationRepoStub{values: map[string]string{SettingKeyOpenAICodexTicketAccountIDs: "[42,41,41]"}}}
	settings := NewSettingService(repo, &config.Config{})
	require.Equal(t, []int64{41, 42}, settings.GetOpenAICodexTicketAccountIDs(ctx))
	repo.err = errors.New("unavailable")
	settings.InvalidateOpenAICodexTicketAccountsCache()
	require.Equal(t, []int64{41, 42}, settings.GetOpenAICodexTicketAccountIDs(ctx))
	require.Equal(t, []int64{-1}, NewSettingService(repo, &config.Config{}).GetOpenAICodexTicketAccountIDs(ctx))
	repo.err = nil
	for _, raw := range []string{"null", "oops", "[-1]", "[0]"} {
		repo.values[SettingKeyOpenAICodexTicketAccountIDs] = raw
		settings.InvalidateOpenAICodexTicketAccountsCache()
		require.Equal(t, []int64{-1}, settings.GetOpenAICodexTicketAccountIDs(ctx))
	}
	repo.values[SettingKeyOpenAICodexTicketAccountIDs] = "[99999]"
	require.Equal(t, []int64{99999}, NewSettingService(repo, &config.Config{}).GetOpenAICodexTicketAccountIDs(ctx), "失效账号不能扩大成全部")
	repo.values[SettingKeyOpenAICodexTicketAccountIDs] = "[]"
	settings.InvalidateOpenAICodexTicketAccountsCache()
	require.Empty(t, settings.GetOpenAICodexTicketAccountIDs(ctx))
}
