//go:build integration

package repository

import (
	"context"
	"testing"

	"github.com/Wei-Shaw/sub2api/migrations"
	"github.com/stretchr/testify/require"
)

func TestCodexTicketBackgroundPolicyMigration(t *testing.T) {
	ctx := context.Background()
	tx, err := integrationDB.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	// 临时表隔离迁移，不修改共享测试库中的真实账号和设置。
	_, err = tx.ExecContext(ctx, `
		CREATE TEMP TABLE settings(key text, value text, updated_at timestamptz);
		CREATE TEMP TABLE accounts(id bigint, platform text, temp_unschedulable_until timestamptz, temp_unschedulable_reason text, updated_at timestamptz, rate_limit_reset_at timestamptz);
		CREATE TEMP TABLE scheduler_outbox(event_type text, account_id bigint);
		CREATE TEMP TABLE codex_ticket_logs(kind text CONSTRAINT codex_ticket_logs_kind_check CHECK (kind IN ('harvest','injection_missing','cooldown')));
		INSERT INTO settings(key,value) VALUES
		('openai_codex_ticket_policy','{"ttl_seconds":7200,"refresh_before_seconds":1200,"max_attempts":5,"failure_cooldown_seconds":1800}'),
		('openai_codex_ticket_account_ids','[363]'), ('unrelated','unchanged');
		INSERT INTO accounts(id,platform,temp_unschedulable_until,temp_unschedulable_reason,rate_limit_reset_at) VALUES
		(1,'openai',NOW()+INTERVAL '1 hour','codex ticket attempts exhausted',NOW()+INTERVAL '2 hours'),
		(2,'openai',NOW()+INTERVAL '1 hour','manual',NULL),
		(3,'anthropic',NOW()+INTERVAL '1 hour','codex ticket attempts exhausted',NULL);
		INSERT INTO codex_ticket_logs(kind) VALUES ('cooldown');`)
	require.NoError(t, err)
	content, err := migrations.FS.ReadFile("241_codex_ticket_background_policy.sql")
	require.NoError(t, err)
	for i := 0; i < 2; i++ {
		_, err = tx.ExecContext(ctx, string(content))
		require.NoError(t, err)
	}
	var policy, scope string
	require.NoError(t, tx.QueryRowContext(ctx, "SELECT value FROM settings WHERE key='openai_codex_ticket_policy'").Scan(&policy))
	require.JSONEq(t, `{"ttl_seconds":7200,"refresh_before_seconds":1200,"harvest_interval_seconds":20,"max_consecutive_failures":30}`, policy)
	require.NoError(t, tx.QueryRowContext(ctx, "SELECT value FROM settings WHERE key='openai_codex_ticket_account_ids'").Scan(&scope))
	require.Equal(t, "[363]", scope)
	var count int
	require.NoError(t, tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM accounts WHERE temp_unschedulable_until IS NOT NULL").Scan(&count))
	require.Equal(t, 2, count)
	require.NoError(t, tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM accounts WHERE id=1 AND temp_unschedulable_reason IS NULL AND rate_limit_reset_at IS NOT NULL").Scan(&count))
	require.Equal(t, 1, count)
	require.NoError(t, tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM scheduler_outbox WHERE account_id=1 AND event_type='account_changed'").Scan(&count))
	require.Equal(t, 1, count, "仅为清理的账号同步缓存")
	_, err = tx.ExecContext(ctx, "INSERT INTO codex_ticket_logs(kind) VALUES ('account_error'),('account_error_write_failed')")
	require.NoError(t, err)
	require.NoError(t, tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM codex_ticket_logs WHERE kind='cooldown'").Scan(&count))
	require.Equal(t, 1, count, "保留历史冷却日志")
}
