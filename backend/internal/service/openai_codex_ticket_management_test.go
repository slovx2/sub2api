package service

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/stretchr/testify/require"
)

type ticketLogMemoryRepo struct {
	mu    sync.Mutex
	items []CodexTicketEvent
}

func (r *ticketLogMemoryRepo) Create(ctx context.Context, event *CodexTicketEvent) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.items = append(r.items, *event)
	return nil
}

func (r *ticketLogMemoryRepo) List(context.Context, CodexTicketLogFilter) (*CodexTicketLogPage, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return &CodexTicketLogPage{Items: append([]CodexTicketEvent{}, r.items...), Total: int64(len(r.items))}, nil
}

func TestCodexTicketManagementHarvestResults(t *testing.T) {
	for _, tc := range []struct {
		name         string
		length, http int
		requestErr   bool
		success      bool
		reason       string
	}{
		{"292", 292, 200, false, true, "accepted"},
		{"332", 332, 200, false, true, "accepted"},
		{"312", 312, 200, false, false, "invalid_length"},
		{"missing", 0, 200, false, false, "missing_state"},
		{"http", 332, 429, false, false, "http_error"},
		{"network", 0, 0, true, false, "request_error"},
		{"invalid-format", 332, 200, false, false, "invalid_format"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logs := &ticketLogMemoryRepo{}
			upstream := &codexTicketFuncUpstream{do: func(*http.Request) (*http.Response, error) {
				if tc.requestErr {
					return nil, errors.New("secret must not be persisted")
				}
				resp := codexTicketResponse()
				resp.StatusCode = tc.http
				resp.Header.Set(openAICodexTurnStateHeader, fakeCodexTicketState(tc.length))
				if tc.name == "invalid-format" {
					resp.Header.Set(openAICodexTurnStateHeader, "badbad"+fakeCodexTicketState(326))
				}
				return resp, nil
			}}
			svc := ticketTestService(t, config.OpenAICodexTicketConfig{Enabled: true, HarvestProxyURL: "http://proxy:8080"}, upstream)
			svc.codexTicketLogRepo = logs
			account := ticketTestAccount(41)
			account.Name, account.Status = "test account", StatusActive
			svc.accountRepo = &codexTicketRefreshRepo{accounts: []Account{*account}}
			svc.probeCodexTicketForTest(context.Background(), account, "gpt-6-astra")
			require.Len(t, logs.items, 1)
			e := logs.items[0]
			require.Equal(t, tc.success, e.Success)
			require.Equal(t, tc.reason, e.Reason)
			require.Equal(t, tc.length, e.Length)
			require.Equal(t, tc.http, e.HTTPStatus)
			require.Equal(t, account.Name, e.AccountName)
			require.Equal(t, account.ID, e.AccountID)
			require.Equal(t, "gpt-6-astra", e.Model)
			require.False(t, e.CreatedAt.IsZero())
			encoded, err := json.Marshal(e)
			require.NoError(t, err)
			require.NotContains(t, string(encoded), "secret")
			require.NotContains(t, string(encoded), "gAAAAA")
			require.False(t, svc.codexTicketCooldownActive(account))
			if tc.success {
				h := http.Header{}
				require.NoError(t, svc.applyOpenAICodexTicket(context.Background(), account, "gpt-6-astra", h))
				require.Len(t, h.Get(openAICodexTurnStateHeader), tc.length)
				overview, err := svc.CodexTicketOverview(context.Background(), 1, 20, false)
				require.NoError(t, err)
				require.Equal(t, 1, overview.ValidTickets)
				require.Equal(t, tc.length, overview.Items[0].Length)
				ticket := svc.lookupOpenAICodexTicket(account, "gpt-6-astra")
				account.Extra = map[string]any{openAICodexTicketExtraKey("gpt-6-astra"): ticket}
				require.True(t, OpenAICodexTicketStatuses(account, svc.openAICodexTicketConfig(), time.Now())[0].Ready)
				ticket.ExpiresAt = time.Now().Add(-time.Second)
				require.False(t, ticket.valid(time.Now(), 292))
			}
		})
	}
}

func TestCodexTicketManagementOverviewScopeAndPagination(t *testing.T) {
	svc := ticketTestService(t, config.OpenAICodexTicketConfig{Enabled: true, AccountIDs: []int64{41, 42}}, nil)
	a, b, c := ticketTestAccount(41), ticketTestAccount(42), ticketTestAccount(43)
	a.Status, b.Status, c.Status = StatusActive, "disabled", StatusActive
	svc.accountRepo = &codexTicketRefreshRepo{accounts: []Account{*a, *b, *c}}
	result, err := svc.CodexTicketOverview(context.Background(), 2, 1, true)
	require.NoError(t, err)
	require.Equal(t, 1, result.Accounts)
	require.Equal(t, 1, result.ProblemAccounts)
	require.Equal(t, 2, result.Total)
	require.Len(t, result.Items, 1)
	require.Equal(t, int64(41), result.Items[0].AccountID)
	require.False(t, result.Items[0].Blocked)
	result, err = svc.CodexTicketOverview(context.Background(), 3, 1, true)
	require.NoError(t, err)
	require.Empty(t, result.Items)
}

func TestCodexTicketManagementCancelledRequestDoesNotHarvestOrCooldown(t *testing.T) {
	svc := ticketTestService(t, config.OpenAICodexTicketConfig{Enabled: true, AccountIDs: []int64{41}}, nil)
	logs := &ticketLogMemoryRepo{}
	svc.codexTicketLogRepo = logs
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.ErrorIs(t, svc.applyOpenAICodexTicket(ctx, ticketTestAccount(41), "gpt-6-astra", http.Header{}), context.Canceled)
	require.NoError(t, svc.applyOpenAICodexTicket(ctx, ticketTestAccount(42), "gpt-6-astra", http.Header{}))
	require.Empty(t, logs.items)
	require.False(t, svc.codexTicketCooldownActive(ticketTestAccount(41)))
}
