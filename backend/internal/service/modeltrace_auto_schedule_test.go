package service

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/modeltrace"
	"github.com/stretchr/testify/require"
)

// modelTraceConfidentReplies 取评分夹具中一组高置信度的真实输出，使整轮探测得到稳定的识别结果。
func modelTraceConfidentReplies(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile("../pkg/modeltrace/parity_fixture.json")
	require.NoError(t, err)
	var fixtures []struct {
		Outputs    []modeltrace.Output    `json:"outputs"`
		Candidates []modeltrace.Candidate `json:"candidates"`
	}
	require.NoError(t, json.Unmarshal(raw, &fixtures))
	for _, f := range fixtures {
		if len(f.Outputs) == 3 && f.Candidates[0].Probability > .99 {
			return []string{f.Outputs[0].Text, f.Outputs[1].Text, f.Outputs[2].Text}
		}
	}
	t.Fatal("夹具中没有高置信度样本")
	return nil
}

func modelTraceScored(protocol, model, prediction string, probability float64) ModelTraceResult {
	return ModelTraceResult{AccountID: 42, Protocol: protocol, Model: model, Status: "success", Prediction: prediction, Probability: probability}
}

func modelTraceFailed(protocol, model string) ModelTraceResult {
	return ModelTraceResult{AccountID: 42, Protocol: protocol, Model: model, Status: "error", Error: "HTTP 429"}
}

func TestModelTraceAutoScheduleDecision(t *testing.T) {
	targets := []ModelTraceTarget{{Protocol: "codex", Model: "a"}, {Protocol: "bps", Model: "b", Expected: "c"}}
	matchA, matchB := modelTraceScored("codex", "a", "a", .99), modelTraceScored("bps", "b", "c", .61)
	on, off := true, false
	for _, tc := range []struct {
		name    string
		targets []ModelTraceTarget
		round   []ModelTraceResult
		want    *bool
	}{
		{"全部匹配", targets, []ModelTraceResult{matchA, matchB}, &on},
		{"明确不匹配", targets, []ModelTraceResult{matchA, modelTraceScored("bps", "b", "other", .99)}, &off},
		{"低置信度", targets, []ModelTraceResult{matchA, modelTraceScored("bps", "b", "c", .6)}, &off},
		{"仅失败", targets, []ModelTraceResult{modelTraceFailed("codex", "a"), modelTraceFailed("bps", "b")}, nil},
		{"匹配与失败", targets, []ModelTraceResult{matchA, modelTraceFailed("bps", "b")}, nil},
		{"失败与不匹配", targets, []ModelTraceResult{modelTraceFailed("codex", "a"), modelTraceScored("bps", "b", "other", .99)}, &off},
		{"缺少目标结果", targets, []ModelTraceResult{matchA}, nil},
		{"空轮次", targets, nil, nil},
		{"没有目标", nil, []ModelTraceResult{matchA}, nil},
		// 轮次中途修改预期：按当前预期重新比较，而不是探测开始时的预期。
		{"按当前预期判定", []ModelTraceTarget{{Protocol: "codex", Model: "a", Expected: "z"}}, []ModelTraceResult{matchA}, &off},
		// 轮次中途删除目标：已不在配置内的结果不参与判定。
		{"忽略已删除目标", targets[:1], []ModelTraceResult{matchA, modelTraceScored("bps", "b", "other", .99)}, &on},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, modelTraceAutoSchedule(tc.targets, tc.round))
		})
	}
}

func TestModelTraceCanOpen(t *testing.T) {
	now := time.Now()
	past, future := now.Add(-time.Minute), now.Add(time.Minute)
	for _, tc := range []struct {
		name   string
		mutate func(*Account)
		want   bool
	}{
		{"正常账号", func(*Account) {}, true},
		{"BPS 403 标记", func(a *Account) { a.Extra[ExcelBPS403DisabledAtKey] = now.UTC().Format(time.RFC3339) }, false},
		{"error 状态", func(a *Account) { a.Status = StatusError }, false},
		{"已过期且自动暂停", func(a *Account) { a.AutoPauseOnExpired, a.ExpiresAt = true, &past }, false},
		{"已过期但不自动暂停", func(a *Account) { a.ExpiresAt = &past }, true},
		{"未过期", func(a *Account) { a.AutoPauseOnExpired, a.ExpiresAt = true, &future }, true},
		{"disabled 状态", func(a *Account) { a.Status = StatusDisabled }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := probeTestAccount()
			tc.mutate(a)
			require.Equal(t, tc.want, modelTraceCanOpen(a, now))
		})
	}
}

func TestModelTraceApplyAutoSchedule(t *testing.T) {
	const model = "gpt-6-astra"
	matched := []ModelTraceResult{modelTraceScored("codex", model, model, .99)}
	mismatched := []ModelTraceResult{modelTraceScored("codex", model, "other", .99)}
	failed := []ModelTraceResult{modelTraceFailed("codex", model)}
	for _, tc := range []struct {
		name   string
		mutate func(*Account, *ModelTraceSettings)
		round  []ModelTraceResult
		before bool
		writes []bool
	}{
		{"全部匹配打开调度", nil, matched, false, []bool{true}},
		{"评分不符关闭调度", nil, mismatched, true, []bool{false}},
		{"请求失败保持关闭", nil, failed, false, nil},
		{"请求失败保持打开", nil, failed, true, nil},
		{"状态已一致不写入", nil, matched, true, nil},
		{"未勾选开关", func(_ *Account, cfg *ModelTraceSettings) { cfg.AutoScheduleAccountIDs = []int64{} }, mismatched, true, nil},
		{"勾选但未纳入探测", func(a *Account, cfg *ModelTraceSettings) {
			cfg.AccountMode, cfg.AccountIDs = "selected", []int64{a.ID + 1}
		}, mismatched, true, nil},
		{"功能停用", func(_ *Account, cfg *ModelTraceSettings) { cfg.Enabled = false }, mismatched, true, nil},
		{"轮次结束时按最新预期", func(_ *Account, cfg *ModelTraceSettings) { cfg.Targets[0].Expected = "other" }, matched, true, []bool{false}},
		{"BPS 403 标记不打开", func(a *Account, _ *ModelTraceSettings) {
			a.Extra[ExcelBPS403DisabledAtKey] = time.Now().UTC().Format(time.RFC3339)
		}, matched, false, nil},
		{"BPS 403 标记仍可关闭", func(a *Account, _ *ModelTraceSettings) {
			a.Extra[ExcelBPS403DisabledAtKey] = time.Now().UTC().Format(time.RFC3339)
		}, mismatched, true, []bool{false}},
		{"error 状态不打开", func(a *Account, _ *ModelTraceSettings) { a.Status = StatusError }, matched, false, nil},
		{"已过期自动暂停不打开", func(a *Account, _ *ModelTraceSettings) {
			expired := time.Now().Add(-time.Minute)
			a.AutoPauseOnExpired, a.ExpiresAt = true, &expired
		}, matched, false, nil},
		{"不可探测账号不写入", func(a *Account, _ *ModelTraceSettings) { a.Type = AccountTypeAPIKey }, mismatched, true, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := *probeTestAccount()
			a.Schedulable = tc.before
			svc, _, cfg := modelTraceReviewService(t, a)
			reader, ok := svc.accounts.(*modelTraceMultiAccounts)
			require.True(t, ok)
			cfg.AutoScheduleAccountIDs = []int64{a.ID}
			if tc.mutate != nil {
				tc.mutate(&reader.accounts[0], &cfg)
			}
			require.NoError(t, svc.settings.SaveModelTraceSettings(context.Background(), cfg))
			svc.applyAutoSchedule(context.Background(), a.ID, tc.round)
			require.Equal(t, tc.writes, reader.schedules)
			want := tc.before
			if len(tc.writes) > 0 {
				want = tc.writes[0]
			}
			require.Equal(t, want, reader.accounts[0].Schedulable)
		})
	}
}

type modelTraceSummaryRepo struct{ ModelTraceRepository }

func (modelTraceSummaryRepo) Latest(context.Context, []int64) (map[int64][]ModelTraceResult, error) {
	return nil, nil
}
func (modelTraceSummaryRepo) States(context.Context, []int64) (map[int64]ModelTraceState, error) {
	return nil, nil
}

func TestModelTraceSummaryAutoSchedule(t *testing.T) {
	a, b := *probeTestAccount(), *probeTestAccount()
	b.ID++
	svc, _, cfg := modelTraceReviewService(t, a, b)
	svc.repo = modelTraceSummaryRepo{}
	summaries := func() map[int64]*ModelTraceSummary {
		t.Helper()
		require.NoError(t, svc.settings.SaveModelTraceSettings(context.Background(), cfg))
		out, err := svc.Summaries(context.Background(), []Account{a, b})
		require.NoError(t, err)
		return out
	}
	cfg.AutoScheduleAccountIDs = []int64{a.ID}
	out := summaries()
	require.True(t, out[a.ID].AutoSchedule)
	require.False(t, out[b.ID].AutoSchedule)
	// 勾选但未纳入探测：不生效，也不产生摘要。
	cfg.AccountMode, cfg.AccountIDs = "selected", []int64{b.ID}
	out = summaries()
	require.NotContains(t, out, a.ID)
	require.False(t, out[b.ID].AutoSchedule)
	cfg.AccountMode, cfg.Enabled = "all", false
	require.False(t, summaries()[a.ID].AutoSchedule)
}

// 整轮经调度循环执行：匹配后打开，预期变化后的下一轮关闭，请求失败的轮次不改写。
func TestModelTraceAutoScheduleFollowsCompletedRounds(t *testing.T) {
	a := *probeTestAccount()
	a.Schedulable = false
	svc, repo, cfg := modelTraceReviewService(t, a)
	reader, ok := svc.accounts.(*modelTraceMultiAccounts)
	require.True(t, ok)
	replies := modelTraceConfidentReplies(t)
	var failing atomic.Bool
	svc.caller = modelTraceCallerFunc(func(_ context.Context, _ *Account, _, _, prompt string) (ProbeReply, error) {
		if failing.Load() {
			return ProbeReply{Status: 403}, fmt.Errorf("HTTP 403")
		}
		for i, challenge := range modeltrace.Challenges {
			if challenge.Prompt == prompt {
				return ProbeReply{Text: replies[i%len(replies)], Status: 200}, nil
			}
		}
		return ProbeReply{}, fmt.Errorf("未知挑战")
	})
	scored := svc.probe(context.Background(), a.ID, cfg.Targets[0])
	require.Equal(t, "success", scored.Status)
	require.Greater(t, scored.Probability, modelTraceMinProbability)
	cfg.Targets[0].Expected = scored.Prediction
	cfg.AutoScheduleAccountIDs = []int64{a.ID}
	require.NoError(t, svc.settings.SaveModelTraceSettings(context.Background(), cfg))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); svc.lead(ctx, modelTraceTestLease{}, cfg) }()
	t.Cleanup(func() { cancel(); <-done })
	// 结果保存先于调度写入，调度写入先于 Finish；等到本轮收尾再读取账号。
	settle := func(rounds int) (bool, []bool) {
		t.Helper()
		require.Eventually(t, func() bool {
			repo.mu.Lock()
			defer repo.mu.Unlock()
			return len(repo.saved) == rounds && !repo.states[a.ID].Running
		}, 2*time.Second, time.Millisecond)
		reader.mu.Lock()
		defer reader.mu.Unlock()
		return reader.accounts[0].Schedulable, append([]bool{}, reader.schedules...)
	}
	rerun := func() {
		t.Helper()
		queued, err := svc.RunNow(ctx)
		require.NoError(t, err)
		require.Equal(t, 1, queued.Accepted)
	}
	schedulable, writes := settle(1)
	require.True(t, schedulable)
	require.Equal(t, []bool{true}, writes)

	// 仅修改预期不打断轮次；下一轮按新预期判定为不匹配并关闭。
	cfg.Targets[0].Expected = "other"
	require.NoError(t, svc.settings.SaveModelTraceSettings(ctx, cfg))
	rerun()
	schedulable, writes = settle(2)
	require.False(t, schedulable)
	require.Equal(t, []bool{true, false}, writes)

	failing.Store(true)
	rerun()
	schedulable, writes = settle(3)
	require.False(t, schedulable)
	require.Equal(t, []bool{true, false}, writes)
}
