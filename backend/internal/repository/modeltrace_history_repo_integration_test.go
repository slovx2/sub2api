//go:build integration

package repository

import (
	"context"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

func modelTraceHistoryFixture(t *testing.T) (*modelTraceRepository, service.ModelTraceSettings, int64) {
	t.Helper()
	ctx := context.Background()
	r := &modelTraceRepository{db: integrationDB}
	a := mustCreateAccount(t, integrationEntClient, &service.Account{Name: "modeltrace-history", Platform: service.PlatformOpenAI, Type: service.AccountTypeOAuth})
	var old string
	oldErr := integrationDB.QueryRowContext(ctx, "SELECT value FROM settings WHERE key='modeltrace'").Scan(&old)
	t.Cleanup(func() {
		_, _ = integrationDB.ExecContext(ctx, "DELETE FROM accounts WHERE id=$1", a.ID)
		if oldErr == nil {
			_, _ = integrationDB.ExecContext(ctx, "UPDATE settings SET value=$1 WHERE key='modeltrace'", old)
		} else {
			_, _ = integrationDB.ExecContext(ctx, "DELETE FROM settings WHERE key='modeltrace'")
		}
	})
	cfg := service.DefaultModelTraceSettings()
	cfg.Enabled, cfg.AccountMode = true, "all"
	cfg.Targets = []service.ModelTraceTarget{{Protocol: "bps", Model: "request", Expected: "expected"}}
	require.NoError(t, r.UpdateSettings(ctx, cfg, []int64{a.ID}))
	ok, err := r.Claim(ctx, a.ID, "owner")
	require.NoError(t, err)
	require.True(t, ok)
	return r, cfg, a.ID
}

func TestModelTraceHistoryStreakPersistenceAndCleanup(t *testing.T) {
	r, cfg, id := modelTraceHistoryFixture(t)
	ctx := context.Background()
	snapshot, err := r.BeginProbe(ctx, id, cfg.Targets[0])
	require.NoError(t, err)
	start := time.Now().UTC().Add(-49 * time.Hour).Truncate(time.Microsecond)
	result := service.ModelTraceResult{AccountID: id, Protocol: "bps", Model: "request", Status: "success", Prediction: "expected", Probability: .99, FinishedAt: start}
	require.NoError(t, r.Save(ctx, result, "owner", *snapshot))
	result.Status = "error"
	result.FinishedAt = time.Now().Add(-time.Hour)
	require.NoError(t, r.Save(ctx, result, "owner", *snapshot))
	// 重新构造仓储模拟进程重启，错误不丢失超过一天的起点。
	r = &modelTraceRepository{db: integrationDB}
	latest, err := r.Latest(ctx, []int64{id})
	require.NoError(t, err)
	require.WithinDuration(t, start, *latest[id][0].MatchedSince, time.Microsecond)
	page, err := r.History(ctx, service.ModelTraceHistoryQuery{AccountID: id})
	require.NoError(t, err)
	require.Len(t, page.Items, 1)
	require.Equal(t, "unknown", page.Items[0].Verdict)
	// 其他实例持有清理锁时不删除；释放后只删除过期历史，不碰起点和最新结果。
	tx, err := integrationDB.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock($1)", modelTraceCleanupLockID)
	require.NoError(t, err)
	require.NoError(t, r.PruneHistory(ctx))
	var count int
	require.NoError(t, integrationDB.QueryRowContext(ctx, "SELECT count(*) FROM modeltrace_history WHERE account_id=$1", id).Scan(&count))
	require.Equal(t, 2, count)
	require.NoError(t, tx.Rollback())
	require.NoError(t, r.PruneHistory(ctx))
	require.NoError(t, integrationDB.QueryRowContext(ctx, "SELECT count(*) FROM modeltrace_history WHERE account_id=$1", id).Scan(&count))
	require.Equal(t, 1, count)
	result.Status = "success"
	result.FinishedAt = time.Now().Add(-30 * time.Minute)
	require.NoError(t, r.Save(ctx, result, "owner", *snapshot))
	latest, err = r.Latest(ctx, []int64{id})
	require.NoError(t, err)
	require.WithinDuration(t, start, *latest[id][0].MatchedSince, time.Microsecond)
	result.Probability = .9
	require.NoError(t, r.Save(ctx, result, "owner", *snapshot))
	latest, err = r.Latest(ctx, []int64{id})
	require.NoError(t, err)
	require.Nil(t, latest[id][0].MatchedSince)
	result.Probability = .99
	result.FinishedAt = time.Now().Truncate(time.Microsecond)
	require.NoError(t, r.Save(ctx, result, "owner", *snapshot))
	latest, err = r.Latest(ctx, []int64{id})
	require.NoError(t, err)
	require.WithinDuration(t, result.FinishedAt, *latest[id][0].MatchedSince, time.Microsecond)
}

func TestModelTraceHistoryConfigGenerationFencing(t *testing.T) {
	for _, change := range []string{"expected", "disable", "account", "target"} {
		t.Run(change, func(t *testing.T) {
			r, cfg, id := modelTraceHistoryFixture(t)
			ctx := context.Background()
			snapshot, err := r.BeginProbe(ctx, id, cfg.Targets[0])
			require.NoError(t, err)
			result := service.ModelTraceResult{AccountID: id, Protocol: "bps", Model: "request", Status: "success", Prediction: "expected", Probability: .99, FinishedAt: time.Now()}
			require.NoError(t, r.Save(ctx, result, "owner", *snapshot))
			updated := cfg
			updated.Targets = append([]service.ModelTraceTarget{}, cfg.Targets...)
			switch change {
			case "expected":
				updated.Targets[0].Expected = "new-expected"
			case "disable":
				updated.Enabled = false
			case "account":
				updated.AccountMode = "selected"
				updated.AccountIDs = []int64{id + 1}
			case "target":
				updated.Targets = []service.ModelTraceTarget{{Protocol: "codex", Model: "other"}}
			}
			require.NoError(t, r.UpdateSettings(ctx, updated, []int64{id}))
			// 甚至恢复相同配置，旧代次也不能重新建立起点。
			require.NoError(t, r.UpdateSettings(ctx, cfg, []int64{id}))
			require.NoError(t, r.Save(ctx, result, "owner", *snapshot))
			latest, err := r.Latest(ctx, []int64{id})
			require.NoError(t, err)
			require.Nil(t, latest[id][0].MatchedSince)
			current, err := r.BeginProbe(ctx, id, cfg.Targets[0])
			require.NoError(t, err)
			require.Greater(t, current.Generation, snapshot.Generation)
			result.FinishedAt = time.Now().Truncate(time.Microsecond)
			require.NoError(t, r.Save(ctx, result, "owner", *current))
			latest, err = r.Latest(ctx, []int64{id})
			require.NoError(t, err)
			require.WithinDuration(t, result.FinishedAt, *latest[id][0].MatchedSince, time.Microsecond)
			cfg.IntervalMinutes = 60
			cfg.Concurrency = 2
			require.NoError(t, r.UpdateSettings(ctx, cfg, []int64{id}))
			unchanged, err := r.BeginProbe(ctx, id, cfg.Targets[0])
			require.NoError(t, err)
			require.Equal(t, current.Generation, unchanged.Generation)
			page, err := r.History(ctx, service.ModelTraceHistoryQuery{AccountID: id})
			require.NoError(t, err)
			for _, entry := range page.Items {
				require.Equal(t, "expected", entry.Expected)
			}
			require.NoError(t, r.Save(ctx, result, "obsolete-owner", *current))
			after, err := r.History(ctx, service.ModelTraceHistoryQuery{AccountID: id})
			require.NoError(t, err)
			require.Len(t, after.Items, len(page.Items))
		})
	}
}

func TestModelTraceHistoryPaginationAndAtomicSave(t *testing.T) {
	r, cfg, id := modelTraceHistoryFixture(t)
	ctx := context.Background()
	snapshot, err := r.BeginProbe(ctx, id, cfg.Targets[0])
	require.NoError(t, err)
	// 同一微秒的多条记录也必须稳定分页。
	result := service.ModelTraceResult{AccountID: id, Protocol: "bps", Model: "request", Status: "success", Prediction: "expected", Probability: .95, FinishedAt: time.Now()}
	for i := 0; i < 53; i++ {
		require.NoError(t, r.Save(ctx, result, "owner", *snapshot))
	}
	first, err := r.History(ctx, service.ModelTraceHistoryQuery{AccountID: id, Protocol: "bps", Model: "request"})
	require.NoError(t, err)
	require.Len(t, first.Items, 50)
	require.NotEmpty(t, first.NextCursor)
	last := first.Items[49]
	second, err := r.History(ctx, service.ModelTraceHistoryQuery{AccountID: id, Before: &service.ModelTraceHistoryCursor{ID: last.ID, FinishedAt: last.FinishedAt}})
	require.NoError(t, err)
	require.Len(t, second.Items, 3)
	require.Empty(t, second.NextCursor)
	require.Greater(t, last.ID, second.Items[0].ID)
	filtered, err := r.History(ctx, service.ModelTraceHistoryQuery{AccountID: id, Protocol: "codex"})
	require.NoError(t, err)
	require.Empty(t, filtered.Items)
	filtered, err = r.History(ctx, service.ModelTraceHistoryQuery{AccountID: id, Model: "nonexistent"})
	require.NoError(t, err)
	require.Empty(t, filtered.Items)
	// 历史插入失败必须回滚最新结果和起点，不能出现半次成功写入。
	_, err = integrationDB.ExecContext(ctx, "ALTER TABLE modeltrace_history ADD CONSTRAINT modeltrace_test_reject CHECK(model <> 'reject')")
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = integrationDB.ExecContext(ctx, "ALTER TABLE modeltrace_history DROP CONSTRAINT modeltrace_test_reject")
	})
	cfg.Targets = append(cfg.Targets, service.ModelTraceTarget{Protocol: "bps", Model: "reject", Expected: "expected"})
	require.NoError(t, r.UpdateSettings(ctx, cfg, []int64{id}))
	rejected, err := r.BeginProbe(ctx, id, cfg.Targets[1])
	require.NoError(t, err)
	result.Model = "reject"
	require.Error(t, r.Save(ctx, result, "owner", *rejected))
	var count int
	require.NoError(t, integrationDB.QueryRowContext(ctx, "SELECT count(*) FROM modeltrace_results WHERE account_id=$1 AND model='reject'", id).Scan(&count))
	require.Zero(t, count)
	var since *time.Time
	require.NoError(t, integrationDB.QueryRowContext(ctx, "SELECT matched_since FROM modeltrace_streaks WHERE account_id=$1 AND model='reject'", id).Scan(&since))
	require.Nil(t, since)
}

func TestModelTraceConfigAtomicReset(t *testing.T) {
	r, cfg, id := modelTraceHistoryFixture(t)
	ctx := context.Background()
	snapshot, err := r.BeginProbe(ctx, id, cfg.Targets[0])
	require.NoError(t, err)
	result := service.ModelTraceResult{AccountID: id, Protocol: "bps", Model: "request", Status: "success", Prediction: "expected", Probability: .99, FinishedAt: time.Now()}
	require.NoError(t, r.Save(ctx, result, "owner", *snapshot))
	var accountBefore, configBefore string
	require.NoError(t, integrationDB.QueryRowContext(ctx, "SELECT row_to_json(a)::text FROM accounts a WHERE id=$1", id).Scan(&accountBefore))
	require.NoError(t, integrationDB.QueryRowContext(ctx, "SELECT value FROM settings WHERE key='modeltrace'").Scan(&configBefore))
	// 强制起点重置失败，配置必须一起回滚，不能出现已换预期但保留旧连续段。
	_, err = integrationDB.ExecContext(ctx, "ALTER TABLE modeltrace_streaks ADD CONSTRAINT modeltrace_test_generation CHECK(generation=1)")
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = integrationDB.ExecContext(ctx, "ALTER TABLE modeltrace_streaks DROP CONSTRAINT IF EXISTS modeltrace_test_generation")
	})
	cfg.Targets[0].Expected = "new-expected"
	require.Error(t, r.UpdateSettings(ctx, cfg, []int64{id}))
	var configAfter string
	require.NoError(t, integrationDB.QueryRowContext(ctx, "SELECT value FROM settings WHERE key='modeltrace'").Scan(&configAfter))
	require.Equal(t, configBefore, configAfter)
	latest, err := r.Latest(ctx, []int64{id})
	require.NoError(t, err)
	require.NotNil(t, latest[id][0].MatchedSince)
	_, err = integrationDB.ExecContext(ctx, "ALTER TABLE modeltrace_streaks DROP CONSTRAINT modeltrace_test_generation")
	require.NoError(t, err)
	require.NoError(t, r.UpdateSettings(ctx, cfg, []int64{id}))
	latest, err = r.Latest(ctx, []int64{id})
	require.NoError(t, err)
	require.Nil(t, latest[id][0].MatchedSince)
	states, err := r.States(ctx, []int64{id})
	require.NoError(t, err)
	require.False(t, states[id].Requested, "仅修改预期不能安排立即重跑")
	var accountAfter string
	require.NoError(t, integrationDB.QueryRowContext(ctx, "SELECT row_to_json(a)::text FROM accounts a WHERE id=$1", id).Scan(&accountAfter))
	require.Equal(t, accountBefore, accountAfter)
}
