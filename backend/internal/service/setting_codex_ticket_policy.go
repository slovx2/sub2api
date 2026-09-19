package service

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

const SettingKeyOpenAICodexTicketPolicy = "openai_codex_ticket_policy"

// 策略整体保存，每轮采票使用固定快照，避免并发更新产生非法组合。
type CodexTicketPolicy struct {
	TTLSeconds             int `json:"ttl_seconds"`
	RefreshBeforeSeconds   int `json:"refresh_before_seconds"`
	MaxAttempts            int `json:"max_attempts"`
	FailureCooldownSeconds int `json:"failure_cooldown_seconds"`
}

func (v CodexTicketPolicy) Validate() error {
	if v.TTLSeconds < 60 || v.TTLSeconds > 86400 {
		return errors.New("票据有效期必须为 60～86400 秒")
	}
	if v.RefreshBeforeSeconds < 0 || v.RefreshBeforeSeconds >= v.TTLSeconds {
		return errors.New("提前刷新必须大于等于 0 且小于票据有效期")
	}
	if v.MaxAttempts < 1 || v.MaxAttempts > 10 {
		return errors.New("最多采票次数必须为 1～10 次（含首次）")
	}
	if v.FailureCooldownSeconds < 60 || v.FailureCooldownSeconds > 86400 {
		return errors.New("失败冷却时间必须为 60～86400 秒")
	}
	return nil
}

type cachedCodexTicketPolicy struct {
	value     CodexTicketPolicy
	expiresAt time.Time
}

func (s *SettingService) codexTicketPolicyFallback() CodexTicketPolicy {
	value := CodexTicketPolicy{TTLSeconds: 3600, RefreshBeforeSeconds: 600, MaxAttempts: 3, FailureCooldownSeconds: 3600}
	if s != nil && s.cfg != nil {
		cfg := s.cfg.Gateway.OpenAICodexTicket
		if cfg.TTLSeconds > 0 {
			value.TTLSeconds = cfg.TTLSeconds
		}
		if cfg.RefreshBeforeSeconds > 0 || (cfg.TTLSeconds > 0 && cfg.RefreshBeforeSeconds == 0) {
			value.RefreshBeforeSeconds = cfg.RefreshBeforeSeconds
		}
	}
	// 配置文件也必须生成合法快照；越界的旧值不传播到 UI 和请求路径。
	value.TTLSeconds = max(60, min(value.TTLSeconds, 86400))
	value.RefreshBeforeSeconds = max(0, min(value.RefreshBeforeSeconds, value.TTLSeconds-1))
	return value
}

func parseCodexTicketPolicy(raw string, fallback CodexTicketPolicy) CodexTicketPolicy {
	var value CodexTicketPolicy
	if json.Unmarshal([]byte(raw), &value) == nil && value.Validate() == nil {
		return value
	}
	return fallback
}

func (s *SettingService) GetOpenAICodexTicketPolicy(ctx context.Context) CodexTicketPolicy {
	if s == nil {
		return s.codexTicketPolicyFallback()
	}
	s.openAICodexTicketPolicyMu.Lock()
	defer s.openAICodexTicketPolicyMu.Unlock()
	previous := s.openAICodexTicketPolicy
	if previous != nil && time.Now().Before(previous.expiresAt) {
		return previous.value
	}
	fallback := s.codexTicketPolicyFallback()
	if previous != nil {
		fallback = previous.value
	}
	value := fallback
	if s.settingRepo != nil {
		readCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		raw, err := s.settingRepo.GetValue(readCtx, SettingKeyOpenAICodexTicketPolicy)
		if errors.Is(err, ErrSettingNotFound) {
			value = s.codexTicketPolicyFallback()
		} else if err == nil {
			value = parseCodexTicketPolicy(raw, fallback)
		}
	}
	s.openAICodexTicketPolicy = &cachedCodexTicketPolicy{value: value, expiresAt: time.Now().Add(5 * time.Second)}
	return value
}

func (s *SettingService) InvalidateOpenAICodexTicketPolicyCache() {
	s.openAICodexTicketPolicyMu.Lock()
	defer s.openAICodexTicketPolicyMu.Unlock()
	if s.openAICodexTicketPolicy != nil {
		s.openAICodexTicketPolicy.expiresAt = time.Time{}
	}
}
