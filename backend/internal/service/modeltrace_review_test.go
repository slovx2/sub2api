package service

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type modelTraceCallerFunc func(context.Context, *Account, string, string, string) (ProbeReply, error)

func (f modelTraceCallerFunc) Call(ctx context.Context, a *Account, protocol, model, prompt string) (ProbeReply, error) {
	return f(ctx, a, protocol, model, prompt)
}

func modelTraceReviewService(t *testing.T, accounts ...Account) (*ModelTraceService, *modelTraceMemoryRepo, ModelTraceSettings) {
	t.Helper()
	cfg := DefaultModelTraceSettings()
	cfg.Enabled, cfg.AccountMode = true, "all"
	cfg.Targets = []ModelTraceTarget{{Protocol: "codex", Model: "gpt-6-astra"}}
	settings := NewSettingService(&modelTraceSettingsStub{}, nil)
	require.NoError(t, settings.SaveModelTraceSettings(context.Background(), cfg))
	repo := &modelTraceMemoryRepo{states: map[int64]ModelTraceState{}, owners: map[int64]string{}}
	svc := &ModelTraceService{settings: settings, accounts: &modelTraceMultiAccounts{accounts: accounts}, repo: repo, wake: make(chan struct{}, 1)}
	return svc, repo, cfg
}

func TestModelTraceAccountSelectionIgnoresOperationalStatus(t *testing.T) {
	for _, status := range []string{StatusActive, StatusDisabled, StatusError, "inactive", ""} {
		t.Run(status, func(t *testing.T) {
			a := *probeTestAccount()
			a.Status = status
			svc, repo, cfg := modelTraceReviewService(t, a)
			svc.caller = modelTraceCallerFunc(func(context.Context, *Account, string, string, string) (ProbeReply, error) {
				return ProbeReply{Status: 403}, fmt.Errorf("HTTP 403")
			})
			queued, err := svc.RunNow(context.Background())
			require.NoError(t, err)
			require.Zero(t, queued.Unavailable)
			require.Equal(t, 1, queued.Accepted)
			result := svc.probe(context.Background(), a.ID, cfg.Targets[0])
			require.Equal(t, "HTTP 403", result.Error)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
			defer cancel()
			svc.lead(ctx, modelTraceTestLease{}, cfg)
			require.Len(t, repo.saved, 1)
			require.Equal(t, status, svc.accounts.(*modelTraceMultiAccounts).accounts[0].Status)
			cfg.AccountMode, cfg.AccountIDs = "selected", []int64{a.ID + 1}
			require.NoError(t, svc.settings.SaveModelTraceSettings(context.Background(), cfg))
			queued, err = svc.RunNow(context.Background())
			require.NoError(t, err)
			require.Zero(t, queued.Accepted, "未选中的账号不探测")
		})
	}
}

func TestModelTraceCredentialFailureStopsCombination(t *testing.T) {
	for _, scenario := range []string{"missing", "expired", "missing_bps_id"} {
		t.Run(scenario, func(t *testing.T) {
			a := *probeTestAccount()
			protocol := "codex"
			switch scenario {
			case "missing":
				delete(a.Credentials, "access_token")
			case "expired":
				a.Credentials["expires_at"] = time.Now().Add(-time.Hour).Format(time.RFC3339)
			case "missing_bps_id":
				delete(a.Credentials, "chatgpt_account_id")
				protocol = "bps"
			}
			svc, _, cfg := modelTraceReviewService(t, a)
			upstream := &probeHTTP{}
			svc.caller = NewOpenAIProbeTransport(upstream, nil)
			cfg.Targets[0].Protocol = protocol
			result := svc.probe(context.Background(), a.ID, cfg.Targets[0])
			require.Equal(t, "error", result.Status)
			require.Len(t, result.Samples, 1)
			require.Nil(t, upstream.request)
			require.EqualValues(t, 1, svc.accounts.(*modelTraceMultiAccounts).gets.Load())
		})
	}
}

func TestModelTraceCompletedScoreSurvivesCancellationBoundary(t *testing.T) {
	a := *probeTestAccount()
	svc, _, cfg := modelTraceReviewService(t, a)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	count := 0
	svc.caller = modelTraceCallerFunc(func(context.Context, *Account, string, string, string) (ProbeReply, error) {
		count++
		if count == 3 {
			cancel()
		}
		return ProbeReply{Text: strings.Repeat("42 ", 330), Status: 200}, nil
	})
	result := svc.probe(ctx, a.ID, cfg.Targets[0])
	require.Equal(t, "success", result.Status)
	require.Empty(t, result.Error)
	require.Len(t, result.Samples, 3)
	require.EqualValues(t, 1, svc.accounts.(*modelTraceMultiAccounts).gets.Load())
}

func TestModelTraceConfigurationChangeReschedulesAffectedAccounts(t *testing.T) {
	for _, change := range []string{"target", "scope", "expected"} {
		t.Run(change, func(t *testing.T) {
			a, b := *probeTestAccount(), *probeTestAccount()
			b.ID++
			svc, repo, cfg := modelTraceReviewService(t, a, b)
			cfg.AccountMode, cfg.AccountIDs = "selected", []int64{a.ID}
			require.NoError(t, svc.settings.SaveModelTraceSettings(context.Background(), cfg))
			for _, id := range []int64{a.ID, b.ID} {
				repo.states[id] = ModelTraceState{NextRunAt: time.Now().Add(30 * time.Minute)}
			}
			switch change {
			case "target":
				cfg.Targets = append(cfg.Targets, ModelTraceTarget{Protocol: "bps", Model: "new-model"})
			case "scope":
				cfg.AccountIDs = append(cfg.AccountIDs, b.ID)
			case "expected":
				cfg.Targets[0].Expected = "another-model"
			}
			require.NoError(t, svc.SaveSettings(context.Background(), cfg))
			require.Equal(t, change == "target", repo.states[a.ID].Requested)
			require.Equal(t, change == "scope", repo.states[b.ID].Requested)
		})
	}
}

func TestModelTraceConfigurationCancellationDoesNotDelay(t *testing.T) {
	a := *probeTestAccount()
	svc, repo, cfg := modelTraceReviewService(t, a)
	caller := &modelTraceBlockingCaller{started: make(chan int64, 20), release: make(chan struct{})}
	svc.caller = caller
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); svc.lead(ctx, modelTraceTestLease{}, cfg) }()
	select {
	case <-caller.started:
	case <-time.After(2 * time.Second):
		t.Fatal("探测未启动")
	}
	// 仅改预期时，原请求继续执行，已有评分可以直接重新比较。
	cfg.Targets[0].Expected = "other"
	require.NoError(t, svc.SaveSettings(ctx, cfg))
	select {
	case <-done:
		t.Fatal("仅修改预期却取消了探测")
	case <-time.After(50 * time.Millisecond):
	}
	cfg.Targets = append(cfg.Targets, ModelTraceTarget{Protocol: "bps", Model: "new-model"})
	require.NoError(t, svc.SaveSettings(ctx, cfg))
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("修改目标未取消旧轮次")
	}
	states, err := repo.States(ctx, []int64{a.ID})
	require.NoError(t, err)
	require.False(t, states[a.ID].Running)
	require.True(t, states[a.ID].Requested)
	require.False(t, states[a.ID].NextRunAt.After(time.Now()))
	// 下一次调度可立即领取，不必等 30 分钟。
	claimed, err := repo.Claim(ctx, a.ID, "new-owner")
	require.NoError(t, err)
	require.True(t, claimed)
}

func TestModelTraceCompletionsReuseAccountList(t *testing.T) {
	a, b := *probeTestAccount(), *probeTestAccount()
	b.ID++
	svc, repo, cfg := modelTraceReviewService(t, a, b)
	cfg.Concurrency = 1
	require.NoError(t, svc.settings.SaveModelTraceSettings(context.Background(), cfg))
	svc.caller = modelTraceCallerFunc(func(context.Context, *Account, string, string, string) (ProbeReply, error) {
		return ProbeReply{Status: 403}, fmt.Errorf("HTTP 403")
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); svc.lead(ctx, modelTraceTestLease{}, cfg) }()
	t.Cleanup(func() { cancel(); <-done })
	require.Eventually(t, func() bool { repo.mu.Lock(); defer repo.mu.Unlock(); return len(repo.saved) == 2 }, 2*time.Second, time.Millisecond)
	reader := svc.accounts.(*modelTraceMultiAccounts)
	require.EqualValues(t, 1, reader.lists.Load())
	require.EqualValues(t, 2, reader.gets.Load())
	// 全选下新增账号在刷新时自动加入，不需要重新保存配置。
	c := *probeTestAccount()
	c.ID += 2
	reader.mu.Lock()
	reader.accounts = append(reader.accounts, c)
	reader.mu.Unlock()
	svc.Wake()
	require.Eventually(t, func() bool { repo.mu.Lock(); defer repo.mu.Unlock(); return len(repo.saved) == 3 }, 2*time.Second, time.Millisecond)
	require.EqualValues(t, 2, reader.lists.Load())
}
