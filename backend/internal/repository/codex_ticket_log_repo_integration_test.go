//go:build integration

package repository

import (
	"context"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

func TestCodexTicketLogsPersistencePaginationAndFilters(t *testing.T) {
	ctx := context.Background()
	repo := NewCodexTicketLogRepository(integrationDB)
	const accountID int64 = 987654321
	t.Cleanup(func() {
		_, _ = integrationDB.ExecContext(ctx, "DELETE FROM codex_ticket_logs WHERE account_id = $1", accountID)
	})
	for i := 0; i < 23; i++ {
		event := &service.CodexTicketEvent{AccountID: accountID, AccountName: "deleted-account", Model: "gpt-6-astra", Kind: "harvest", Length: 332, HTTPStatus: 200, Success: i%2 == 0, Reason: "accepted", CreatedAt: time.Now()}
		if i == 22 {
			event.Kind, event.Success, event.Reason = "injection_missing", false, "no_valid_ticket"
		}
		require.NoError(t, repo.Create(ctx, event))
	}
	// 重建仓储仍可读取历史；账号不存在也不丢记录。
	repo = NewCodexTicketLogRepository(integrationDB)
	first, err := repo.List(ctx, service.CodexTicketLogFilter{Page: 1, PageSize: 20, AccountID: accountID})
	require.NoError(t, err)
	require.Len(t, first.Items, 20)
	require.EqualValues(t, 23, first.Total)
	require.Equal(t, service.CodexTicketLogSummary{Attempts: 22, Success: 11, Failure: 11, InjectionMissing: 1}, first.Summary)
	second, err := repo.List(ctx, service.CodexTicketLogFilter{Page: 2, PageSize: 20, AccountID: accountID})
	require.NoError(t, err)
	require.Len(t, second.Items, 3)
	require.Greater(t, first.Items[19].ID, second.Items[0].ID)
	for result, count := range map[string]int64{"success": 11, "failure": 11, "injection_missing": 1} {
		page, err := repo.List(ctx, service.CodexTicketLogFilter{AccountID: accountID, Result: result})
		require.NoError(t, err)
		require.Equal(t, count, page.Total)
		require.Equal(t, first.Summary, page.Summary)
	}
	empty, err := repo.List(ctx, service.CodexTicketLogFilter{AccountID: accountID + 1})
	require.NoError(t, err)
	require.Empty(t, empty.Items)
	require.Zero(t, empty.Total)
}
