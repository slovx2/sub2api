//go:build integration

package repository

import (
	"context"
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

func TestModelTraceRepositoryIsolationAndLeases(t *testing.T) {
	ctx := context.Background()
	repo := &modelTraceRepository{db: integrationDB}
	account := mustCreateAccount(t, integrationEntClient, &service.Account{Name: "modeltrace-isolation", Platform: service.PlatformOpenAI, Type: service.AccountTypeOAuth})
	t.Cleanup(func() { _, _ = integrationDB.ExecContext(ctx, "DELETE FROM accounts WHERE id=$1", account.ID) })
	snapshot := func() string {
		var raw []byte
		require.NoError(t, integrationDB.QueryRowContext(ctx, "SELECT row_to_json(a) FROM accounts a WHERE id=$1", account.ID).Scan(&raw))
		return string(raw)
	}
	before := snapshot()
	lease, err := repo.Acquire(ctx)
	require.NoError(t, err)
	require.NotNil(t, lease)
	defer lease.Close()
	second, err := repo.Acquire(ctx)
	require.NoError(t, err)
	require.Nil(t, second)
	require.NoError(t, lease.Check(ctx))
	queued, err := repo.Enqueue(ctx, []int64{account.ID})
	require.NoError(t, err)
	require.Equal(t, 1, queued.Accepted)
	var claimed atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, e := repo.Claim(ctx, account.ID, "owner")
			if e == nil && ok {
				claimed.Add(1)
			}
		}()
	}
	wg.Wait()
	require.EqualValues(t, 1, claimed.Load())
	queued, err = repo.Enqueue(ctx, []int64{account.ID})
	require.NoError(t, err)
	require.Equal(t, 1, queued.Running)
	result := service.ModelTraceResult{AccountID: account.ID, Protocol: "bps", Model: "gpt-6-astra", Status: "success", Probability: .99, Prediction: "gpt-6-astra", StartedAt: time.Now(), FinishedAt: time.Now()}
	require.NoError(t, repo.Save(ctx, result, "owner", service.ModelTraceProbeSnapshot{Target: service.ModelTraceTarget{Protocol: result.Protocol, Model: result.Model}}))
	result.Status = "error"
	result.Error = "HTTP 403"
	require.NoError(t, repo.Save(ctx, result, "owner", service.ModelTraceProbeSnapshot{Target: service.ModelTraceTarget{Protocol: result.Protocol, Model: result.Model}}))
	results, err := repo.Latest(ctx, []int64{account.ID})
	require.NoError(t, err)
	require.Len(t, results[account.ID], 1)
	require.Equal(t, "error", results[account.ID][0].Status)
	require.NoError(t, repo.Recover(ctx, 30*time.Minute))
	result.Status = "success"
	require.NoError(t, repo.Save(ctx, result, "owner", service.ModelTraceProbeSnapshot{Target: service.ModelTraceTarget{Protocol: result.Protocol, Model: result.Model}}))
	results, err = repo.Latest(ctx, []int64{account.ID})
	require.NoError(t, err)
	require.Equal(t, "error", results[account.ID][0].Status, "旧执行者不能覆盖恢复后的结果")
	states, err := repo.States(ctx, []int64{account.ID})
	require.NoError(t, err)
	require.False(t, states[account.ID].Running)
	require.WithinDuration(t, time.Now().Add(30*time.Minute), states[account.ID].NextRunAt, time.Minute)
	// 已完成账号和在途账号的配置首轮都应持久化，旧轮次 Finish 不可吞掉请求。
	require.NoError(t, repo.Reschedule(ctx, []int64{account.ID}))
	ok, err := repo.Claim(ctx, account.ID, "config-owner")
	require.NoError(t, err)
	require.True(t, ok)
	require.NoError(t, repo.Reschedule(ctx, []int64{account.ID}))
	require.NoError(t, repo.Finish(ctx, account.ID, "config-owner", 30*time.Minute))
	states, err = repo.States(ctx, []int64{account.ID})
	require.NoError(t, err)
	require.True(t, states[account.ID].Requested)
	ok, err = repo.Claim(ctx, account.ID, "new-config-owner")
	require.NoError(t, err)
	require.True(t, ok)
	require.NoError(t, repo.Finish(ctx, account.ID, "new-config-owner", 30*time.Minute))
	ok, err = repo.Claim(ctx, account.ID, "too-early")
	require.NoError(t, err)
	require.False(t, ok, "新轮完成后恢复正常间隔")
	require.JSONEq(t, before, snapshot(), "全部调度和结果写入不影响账号行")
	var value map[string]any
	require.NoError(t, json.Unmarshal([]byte(snapshot()), &value))
}
