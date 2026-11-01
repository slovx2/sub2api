//go:build unit

package service

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// realCodex429Headers 还原 2026-10-06 线上事件（账号 26）的 429 响应头：
// 7d 窗口 100%（靠积分续命）、5h 窗口 93%。
// 修复前该响应会把账号冻结到周窗口重置（312384s≈3.6 天），
// 期间账号被调度器完全排除（pool=0），尽管上游实测仍可凭积分正常服务。
func realCodex429Headers() http.Header {
	headers := http.Header{}
	headers.Set("x-codex-primary-used-percent", "93") // 5h
	headers.Set("x-codex-primary-window-minutes", "300")
	headers.Set("x-codex-primary-reset-after-seconds", "10085")
	headers.Set("x-codex-secondary-used-percent", "100") // 7d
	headers.Set("x-codex-secondary-window-minutes", "10080")
	headers.Set("x-codex-secondary-reset-after-seconds", "312384")
	headers.Set("x-codex-plan-type", "plus")
	return headers
}

func realCodex429HeadersWithCredits() http.Header {
	headers := realCodex429Headers()
	headers.Set("x-codex-credits-has-credits", "True")
	headers.Set("x-codex-credits-balance", "2997.3994180000")
	headers.Set("x-codex-credits-unlimited", "False")
	return headers
}

func creditsSnapshotExtra(fetchedAt time.Time, hasCredits bool, unlimited bool, balance string) map[string]any {
	return map[string]any{
		openaiQuotaCreditsKey: map[string]any{
			"credits": map[string]any{
				"has_credits": hasCredits,
				"unlimited":   unlimited,
				"balance":     balance,
			},
			"fetched_at": fetchedAt.Unix(),
		},
	}
}

func TestOpenAICodexCreditsAvailable_ResponseHeaders(t *testing.T) {
	account := &Account{ID: 1, Platform: PlatformOpenAI, Type: AccountTypeOAuth}
	now := time.Now()

	cases := []struct {
		name    string
		mutate  func(http.Header)
		want    bool
		comment string
	}{
		{"has-credits with positive balance", func(h http.Header) {}, true, ""},
		{"has-credits false", func(h http.Header) {
			h.Set("x-codex-credits-has-credits", "False")
		}, false, ""},
		{"has-credits true but zero balance", func(h http.Header) {
			h.Set("x-codex-credits-balance", "0")
		}, false, ""},
		{"has-credits true and unlimited", func(h http.Header) {
			h.Set("x-codex-credits-unlimited", "True")
			h.Del("x-codex-credits-balance")
		}, true, "unlimited 时不依赖余额"},
		{"no credits headers at all", func(h http.Header) {
			h.Del("x-codex-credits-has-credits")
			h.Del("x-codex-credits-balance")
			h.Del("x-codex-credits-unlimited")
		}, false, "无积分头时回退本地快照，账号无快照 → 不豁免"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			headers := realCodex429HeadersWithCredits()
			tc.mutate(headers)
			require.Equal(t, tc.want, openAICodexCreditsAvailable(account, headers, now))
		})
	}
}

func TestOpenAICodexCreditsAvailable_SnapshotFallback(t *testing.T) {
	now := time.Now()
	headers := realCodex429Headers() // 无积分响应头，强制走快照

	t.Run("fresh snapshot with credits", func(t *testing.T) {
		account := &Account{ID: 2, Platform: PlatformOpenAI, Extra: creditsSnapshotExtra(now.Add(-time.Hour), true, false, "2997.3994180000")}
		require.True(t, openAICodexCreditsAvailable(account, headers, now))
	})

	t.Run("stale snapshot does not qualify", func(t *testing.T) {
		account := &Account{ID: 3, Platform: PlatformOpenAI, Extra: creditsSnapshotExtra(now.Add(-openAICodexCreditsSnapshotStaleAfter-time.Minute), true, false, "100")}
		require.False(t, openAICodexCreditsAvailable(account, headers, now))
	})

	t.Run("no credits in snapshot", func(t *testing.T) {
		account := &Account{ID: 4, Platform: PlatformOpenAI, Extra: creditsSnapshotExtra(now, false, false, "0")}
		require.False(t, openAICodexCreditsAvailable(account, headers, now))
	})

	t.Run("snapshot unlimited", func(t *testing.T) {
		account := &Account{ID: 5, Platform: PlatformOpenAI, Extra: creditsSnapshotExtra(now, true, true, "0")}
		require.True(t, openAICodexCreditsAvailable(account, headers, now))
	})

	t.Run("account without extra", func(t *testing.T) {
		account := &Account{ID: 6, Platform: PlatformOpenAI}
		require.False(t, openAICodexCreditsAvailable(account, headers, now))
	})
}

// openAI429CreditsRepo 在既有 fake 的基础上记录 SetRateLimited 的解冻时刻，
// 用于区分"窗口级冻结（数天）"与"秒级短冷却"。
type openAI429CreditsRepo struct {
	openAI429SnapshotRepo
	rateLimitedUntil time.Time
}

func (r *openAI429CreditsRepo) SetRateLimited(_ context.Context, id int64, until time.Time) error {
	r.rateLimitedID = id
	r.rateLimitedUntil = until
	return nil
}

// TestHandle429_OpenAIWithCreditsDefersToShortCooldown 回归测试：
// 7d=100% 但积分可用时，429 不得冻结到周窗口重置（修复前为 +3.6 天）。
func TestHandle429_OpenAIWithCreditsDefersToShortCooldown(t *testing.T) {
	repo := &openAI429CreditsRepo{}
	svc := NewRateLimitService(repo, nil, nil, nil, nil)
	account := &Account{ID: 126, Platform: PlatformOpenAI, Type: AccountTypeOAuth}

	svc.handle429(context.Background(), account, realCodex429HeadersWithCredits(), nil)

	require.Equal(t, account.ID, repo.rateLimitedID, "仍写入短冷却，避免瞬时反复撞击上游")
	require.NotZero(t, repo.rateLimitedUntil)
	require.Positive(t, time.Until(repo.rateLimitedUntil))
	require.Less(t, time.Until(repo.rateLimitedUntil), time.Hour,
		"应为秒级短冷却（可配置），而不是窗口级冻结")
	require.NotEmpty(t, repo.updatedExtra, "codex 用量快照仍应被持久化")
	require.Equal(t, 100.0, repo.updatedExtra["codex_7d_used_percent"])
}

// TestHandle429_OpenAICreditsViaSnapshotDefersToShortCooldown 与上同，
// 但积分信息只存在于本地快照（429 响应未携带积分头）。
func TestHandle429_OpenAICreditsViaSnapshotDefersToShortCooldown(t *testing.T) {
	repo := &openAI429CreditsRepo{}
	svc := NewRateLimitService(repo, nil, nil, nil, nil)
	account := &Account{
		ID:       127,
		Platform: PlatformOpenAI,
		Type:     AccountTypeOAuth,
		Extra:    creditsSnapshotExtra(time.Now(), true, false, "2997.3994180000"),
	}

	svc.handle429(context.Background(), account, realCodex429Headers(), nil)

	require.Equal(t, account.ID, repo.rateLimitedID)
	require.Less(t, time.Until(repo.rateLimitedUntil), time.Hour)
}

// TestHandle429_OpenAIWithoutCreditsStillFreezesUntilWindowReset 无积分时保持原行为：
// 窗口耗尽仍冻结到周窗口重置（确认修复未放宽既有语义）。
func TestHandle429_OpenAIWithoutCreditsStillFreezesUntilWindowReset(t *testing.T) {
	repo := &openAI429CreditsRepo{}
	svc := NewRateLimitService(repo, nil, nil, nil, nil)
	account := &Account{ID: 128, Platform: PlatformOpenAI, Type: AccountTypeOAuth}

	svc.handle429(context.Background(), account, realCodex429Headers(), nil)

	require.Equal(t, account.ID, repo.rateLimitedID)
	require.Greater(t, time.Until(repo.rateLimitedUntil), 72*time.Hour,
		"无积分时应保持原行为：冻结到周窗口重置")
}

// 当前网关在持久化限流之前还会更新内存熔断，两个路径必须使用同一积分判据。
func TestOpenAICredits429GatewayRuntime(t *testing.T) {
	for _, snapshotOnly := range []bool{false, true} {
		for _, retryExpired := range []bool{false, true} {
			t.Run(fmt.Sprintf("snapshot=%t/expired=%t", snapshotOnly, retryExpired), func(t *testing.T) {
				repo := &oauth429RateLimitRepo{}
				rateLimits := NewRateLimitService(repo, nil, nil, nil, nil)
				gateway := &OpenAIGatewayService{rateLimitService: rateLimits}
				rateLimits.SetAccountRuntimeBlocker(gateway)
				account := &Account{ID: 129, Platform: PlatformOpenAI, Type: AccountTypeOAuth}
				headers := realCodex429HeadersWithCredits()
				if snapshotOnly {
					headers = realCodex429Headers()
					account.Extra = creditsSnapshotExtra(time.Now(), true, false, "2997.4")
				}
				if retryExpired {
					gateway.openaiOAuth429RetryStartedAt.Store(account.ID, time.Now().Add(-openAIOAuth429RetryWindow-time.Second))
				}
				gateway.handleOpenAIAccountUpstreamError(context.Background(), account, http.StatusTooManyRequests, headers, nil)
				if retryExpired {
					require.Equal(t, 1, repo.setRateLimitedCalls)
					require.Less(t, time.Until(repo.lastRateLimitedUntil), time.Minute)
					until, ok := gateway.openaiAccountRuntimeBlockUntil.Load(account.ID)
					require.True(t, ok)
					require.Less(t, time.Until(until.(time.Time)), time.Minute)
				} else {
					require.False(t, gateway.isOpenAIAccountRuntimeBlocked(account))
					require.Zero(t, repo.setRateLimitedCalls)
					require.True(t, gateway.ShouldRetryOpenAIOAuth429(account, headers, nil))
				}
			})
		}
	}
}

func TestOpenAICredits429PreservesQuotaPauseAndManualThreshold(t *testing.T) {
	now := time.Now()
	account := &Account{
		ID: 130, Platform: PlatformOpenAI, Type: AccountTypeOAuth,
		Extra:       creditsSnapshotExtra(now, true, false, "62500"),
		Credentials: map[string]any{"account_scheduling_threshold": 99},
	}
	account.Extra["codex_7d_used_percent"] = 100.0
	account.Extra["codex_7d_reset_at"] = now.Add(24 * time.Hour).Format(time.RFC3339)
	account.Extra["codex_usage_updated_at"] = now.Format(time.RFC3339)
	ctx := withOpenAIQuotaAutoPauseSettings(context.Background(), OpsOpenAIAccountQuotaAutoPauseSettings{
		DefaultThreshold5h: 1, DefaultThreshold7d: 1,
	})
	paused, _ := shouldAutoPauseOpenAIAccountByQuota(ctx, account)
	require.True(t, paused, "默认设置在额度耗尽后暂停，即使账号有积分")
	account.Extra["auto_pause_5h_disabled"] = true
	account.Extra["auto_pause_7d_disabled"] = true
	paused, _ = shouldAutoPauseOpenAIAccountByQuota(ctx, account)
	require.False(t, paused, "显式关闭窗口暂停后才允许续跑")
	decision := EvaluateAccountSchedulingThreshold(account, map[string]int{PlatformOpenAI: 100}, now)
	require.True(t, decision.ShouldPause, "用户手动阈值仍然优先")
}
