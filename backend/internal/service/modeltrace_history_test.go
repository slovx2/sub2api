package service

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestModelTraceStreakTransitions(t *testing.T) {
	old := time.Now().Add(-72 * time.Hour)
	now := time.Now()
	for _, tc := range []struct {
		name, status, prediction string
		probability              float64
		keep, clear              bool
	}{
		{"匹配", "success", "expected", .91, true, false},
		{"恰好90", "success", "expected", .9, false, true},
		{"低概率", "success", "expected", .89, false, true},
		{"明确不匹配", "success", "other", .99, false, true},
		{"网络失败", "error", "", 0, true, false},
		{"样本不足", "error", "", 0, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := ModelTraceResult{Status: tc.status, Prediction: tc.prediction, Probability: tc.probability, FinishedAt: now}
			since := ModelTraceNextMatchedSince(&old, r, "expected")
			if tc.keep {
				require.Equal(t, &old, since)
			}
			if tc.clear {
				require.Nil(t, since)
			}
			first := ModelTraceNextMatchedSince(nil, r, "expected")
			if ModelTraceVerdict(r, "expected") == "matched" {
				require.Equal(t, &now, first)
			} else {
				require.Nil(t, first)
			}
		})
	}
}

func TestModelTraceStreakSummaryVisibility(t *testing.T) {
	now := time.Now().Add(-49 * time.Hour)
	cfg := DefaultModelTraceSettings()
	cfg.Enabled, cfg.AccountMode = true, "all"
	cfg.Targets = []ModelTraceTarget{{Protocol: "bps", Model: "requested", Expected: "expected"}}
	r := ModelTraceResult{AccountID: 42, Protocol: "bps", Model: "requested", Status: "success", Prediction: "expected", Probability: .99, MatchedSince: &now, StreakExpected: "expected"}
	summary := modelTraceSummary(cfg, []ModelTraceResult{r}, true)
	require.Equal(t, &now, summary.Details[0].MatchedSince)
	require.Equal(t, 1, summary.Matched)
	for _, tc := range []string{"error", "uncertain", "mismatch", "disabled", "removed", "changed"} {
		t.Run(tc, func(t *testing.T) {
			config, result := cfg, r
			switch tc {
			case "error":
				result.Status = "error"
			case "uncertain":
				result.Probability = .9
			case "mismatch":
				result.Prediction = "other"
			case "disabled":
				config.Enabled = false
			case "removed":
				config.AccountMode = "selected"
				config.AccountIDs = []int64{99}
			case "changed":
				result.StreakExpected = "old-expected"
			}
			summary := modelTraceSummary(config, []ModelTraceResult{result}, false)
			require.Nil(t, summary.Details[0].MatchedSince)
		})
	}
}

type modelTraceCleanupStub struct {
	ModelTraceRepository
	calls atomic.Int32
}

func (r *modelTraceCleanupStub) PruneHistory(context.Context) error { r.calls.Add(1); return nil }

func TestModelTraceCleanupRunsWithoutEnabledSettings(t *testing.T) {
	repo := &modelTraceCleanupStub{}
	svc := &ModelTraceService{repo: repo}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); svc.maintainHistory(ctx) }()
	require.Eventually(t, func() bool { return repo.calls.Load() == 1 }, time.Second, time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("清理协程未退出")
	}
}

func TestModelTraceHistoryInvalidFilters(t *testing.T) {
	svc := &ModelTraceService{}
	for _, tc := range []struct {
		id                      int64
		protocol, model, cursor string
	}{
		{0, "", "", ""}, {1, "invalid", "", ""}, {1, "", "", "!"}, {1, "", "", "e30"},
	} {
		_, err := svc.History(context.Background(), tc.id, tc.protocol, tc.model, tc.cursor)
		require.Error(t, err)
	}
}
