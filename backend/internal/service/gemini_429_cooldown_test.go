//go:build unit

package service

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/stretchr/testify/require"
)

type gemini429CooldownRepo struct {
	mockAccountRepoForGemini
	setRateLimitedCalls int
	lastResetAt         time.Time
}

func (r *gemini429CooldownRepo) SetRateLimited(_ context.Context, _ int64, resetAt time.Time) error {
	r.setRateLimitedCalls++
	r.lastResetAt = resetAt
	return nil
}

func TestHandleGeminiUpstreamError_UsesConfiguredCooldownForGemini429(t *testing.T) {
	tests := []struct {
		name            string
		body            []byte
		wantMin         time.Duration
		wantMax         time.Duration
		cooldownMinutes int
	}{
		{
			name:            "daily quota 文案改走配置冷却",
			body:            []byte(`{"error":{"message":"quota per day exceeded"}}`),
			wantMin:         110 * time.Second,
			wantMax:         130 * time.Second,
			cooldownMinutes: 2,
		},
		{
			name:            "无 reset 信息改走配置冷却",
			body:            []byte(`{"error":{"message":"rate limit"}}`),
			wantMin:         110 * time.Second,
			wantMax:         130 * time.Second,
			cooldownMinutes: 2,
		},
		{
			name:            "显式 quotaResetDelay 仍优先使用上游时间",
			body:            []byte(`{"error":{"details":[{"metadata":{"quotaResetDelay":"12s"}}]}}`),
			wantMin:         10 * time.Second,
			wantMax:         14 * time.Second,
			cooldownMinutes: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &gemini429CooldownRepo{}
			svc := &GeminiMessagesCompatService{
				accountRepo: repo,
				cfg: &config.Config{
					RateLimit: config.RateLimitConfig{
						Gemini429CooldownMinutes: tt.cooldownMinutes,
					},
				},
			}
			account := &Account{
				ID:       1,
				Type:     AccountTypeAPIKey,
				Platform: PlatformGemini,
			}

			start := time.Now()
			svc.handleGeminiUpstreamError(context.Background(), account, http.StatusTooManyRequests, http.Header{}, tt.body)

			require.Equal(t, 1, repo.setRateLimitedCalls)
			wait := repo.lastResetAt.Sub(start)
			require.GreaterOrEqual(t, wait, tt.wantMin)
			require.LessOrEqual(t, wait, tt.wantMax)
		})
	}
}

func TestRateLimitServiceHandleUpstreamError_Gemini429UsesConfiguredCooldown(t *testing.T) {
	tests := []struct {
		name            string
		body            []byte
		wantMin         time.Duration
		wantMax         time.Duration
		cooldownMinutes int
	}{
		{
			name:            "daily quota 文案不再挂到次日",
			body:            []byte(`{"error":{"message":"quota per day exceeded"}}`),
			wantMin:         170 * time.Second,
			wantMax:         190 * time.Second,
			cooldownMinutes: 3,
		},
		{
			name:            "无 reset 信息使用 Gemini 专属冷却",
			body:            []byte(`{"error":{"message":"rate limited"}}`),
			wantMin:         170 * time.Second,
			wantMax:         190 * time.Second,
			cooldownMinutes: 3,
		},
		{
			name:            "显式 reset 信息继续优先使用",
			body:            []byte(`{"error":{"details":[{"metadata":{"quotaResetDelay":"8s"}}]}}`),
			wantMin:         6 * time.Second,
			wantMax:         10 * time.Second,
			cooldownMinutes: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &gemini429CooldownRepo{}
			svc := NewRateLimitService(repo, nil, &config.Config{
				RateLimit: config.RateLimitConfig{
					Gemini429CooldownMinutes: tt.cooldownMinutes,
				},
			}, nil, nil)
			account := &Account{
				ID:       2,
				Type:     AccountTypeAPIKey,
				Platform: PlatformGemini,
			}

			start := time.Now()
			shouldDisable := svc.HandleUpstreamError(context.Background(), account, http.StatusTooManyRequests, http.Header{}, tt.body)

			require.False(t, shouldDisable)
			require.Equal(t, 1, repo.setRateLimitedCalls)
			wait := repo.lastResetAt.Sub(start)
			require.GreaterOrEqual(t, wait, tt.wantMin)
			require.LessOrEqual(t, wait, tt.wantMax)
		})
	}
}
