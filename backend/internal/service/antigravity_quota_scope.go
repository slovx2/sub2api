package service

import (
	"context"
	"strings"
	"time"
)

const (
	antigravityRateLimitScopeClaude      = "claude"
	antigravityRateLimitScopeGeminiText  = "gemini_text"
	antigravityRateLimitScopeGeminiImage = "gemini_image"
	antigravityQuotaScopesLegacyKey      = "antigravity_quota_scopes"
)

var antigravityAllScopes = []string{
	antigravityRateLimitScopeClaude,
	antigravityRateLimitScopeGeminiText,
	antigravityRateLimitScopeGeminiImage,
}

func normalizeAntigravityModelName(model string) string {
	normalized := normalizeAntigravityRequestedModel(model)
	normalized = strings.TrimPrefix(normalized, "models/")
	return normalized
}

// resolveAntigravityScopeKey 根据模型名解析 Antigravity scope 限流 key。
// 返回空字符串表示无法归类到 scope。
func resolveAntigravityScopeKey(model string) string {
	normalizedModel := normalizeAntigravityModelName(model)
	if normalizedModel == "" {
		return ""
	}

	switch {
	case strings.HasPrefix(normalizedModel, "claude-"):
		return antigravityRateLimitScopeClaude
	case strings.HasPrefix(normalizedModel, "gemini-"):
		if isImageGenerationModel(normalizedModel) {
			return antigravityRateLimitScopeGeminiImage
		}
		return antigravityRateLimitScopeGeminiText
	default:
		return ""
	}
}

// resolveAntigravityModelKey 根据请求模型解析限流 key。
// 当前策略：优先返回 scope key；无法归类时兜底为模型名，避免丢失限流语义。
func resolveAntigravityModelKey(requestedModel string) string {
	if scopeKey := resolveAntigravityScopeKey(requestedModel); scopeKey != "" {
		return scopeKey
	}
	return normalizeAntigravityModelName(requestedModel)
}

// IsSchedulableForModel 结合模型级限流判断是否可调度。
// 保持旧签名以兼容既有调用方；默认使用 context.Background()。
func (a *Account) IsSchedulableForModel(requestedModel string) bool {
	return a.IsSchedulableForModelWithContext(context.Background(), requestedModel)
}

func (a *Account) IsSchedulableForModelWithContext(ctx context.Context, requestedModel string) bool {
	if a == nil {
		return false
	}
	if !a.IsSchedulable() {
		return false
	}
	if a.isModelRateLimitedWithContext(ctx, requestedModel) {
		return false
	}
	return true
}

// GetRateLimitRemainingTime 获取限流剩余时间（模型级限流）
// 返回 0 表示未限流或已过期
func (a *Account) GetRateLimitRemainingTime(requestedModel string) time.Duration {
	return a.GetRateLimitRemainingTimeWithContext(context.Background(), requestedModel)
}

// GetRateLimitRemainingTimeWithContext 获取限流剩余时间（模型级限流）
// 返回 0 表示未限流或已过期
func (a *Account) GetRateLimitRemainingTimeWithContext(ctx context.Context, requestedModel string) time.Duration {
	if a == nil {
		return 0
	}
	return a.GetModelRateLimitRemainingTimeWithContext(ctx, requestedModel)
}

// GetAntigravityScopeRateLimits 返回当前生效的 scope 级限流剩余秒数。
// 兼容两种数据来源：
// 1. 当前版本的 extra.model_rate_limits（scope key）
// 2. 历史版本的 extra.antigravity_quota_scopes
func (a *Account) GetAntigravityScopeRateLimits() map[string]int64 {
	if a == nil || a.Platform != PlatformAntigravity || a.Extra == nil {
		return nil
	}

	now := time.Now()
	result := make(map[string]int64)

	collect := func(raw map[string]any) {
		for _, scope := range antigravityAllScopes {
			remaining := parseScopeRemainingSeconds(raw, scope, now)
			if remaining <= 0 {
				continue
			}
			if existing, ok := result[scope]; !ok || remaining > existing {
				result[scope] = remaining
			}
		}
	}

	if rawModelLimits, ok := a.Extra[modelRateLimitsKey].(map[string]any); ok {
		collect(rawModelLimits)
	}
	if rawLegacyScopes, ok := a.Extra[antigravityQuotaScopesLegacyKey].(map[string]any); ok {
		collect(rawLegacyScopes)
	}

	if len(result) == 0 {
		return nil
	}
	return result
}

func parseScopeRemainingSeconds(raw map[string]any, scope string, now time.Time) int64 {
	if raw == nil || strings.TrimSpace(scope) == "" {
		return 0
	}

	entry, ok := raw[scope].(map[string]any)
	if !ok || entry == nil {
		return 0
	}

	resetRaw, ok := entry["rate_limit_reset_at"].(string)
	if !ok || strings.TrimSpace(resetRaw) == "" {
		return 0
	}

	resetAt, err := time.Parse(time.RFC3339, resetRaw)
	if err != nil || !now.Before(resetAt) {
		return 0
	}

	remaining := int64(time.Until(resetAt).Seconds())
	if remaining <= 0 {
		return 0
	}
	return remaining
}
