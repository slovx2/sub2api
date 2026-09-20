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
	HarvestIntervalSeconds int `json:"harvest_interval_seconds"`
	MaxConsecutiveFailures int `json:"max_consecutive_failures"`
}

func (v CodexTicketPolicy) Validate() error {
	if v.TTLSeconds < 60 || v.TTLSeconds > 86400 {
		return errors.New("票据有效期必须为 60～86400 秒")
	}
	if v.RefreshBeforeSeconds < 0 || v.RefreshBeforeSeconds >= v.TTLSeconds {
		return errors.New("提前刷新必须大于等于 0 且小于票据有效期")
	}
	if v.HarvestIntervalSeconds < 1 || v.HarvestIntervalSeconds > 86400 {
		return errors.New("采票间隔必须为 1～86400 秒")
	}
	if v.MaxConsecutiveFailures < 1 || v.MaxConsecutiveFailures > 10000 {
		return errors.New("连续失败阈值必须为 1～10000 次")
	}
	return nil
}

type cachedCodexTicketPolicy struct {
	value     CodexTicketPolicy
	expiresAt time.Time
}

func (s *SettingService) codexTicketPolicyFallback() CodexTicketPolicy {
	value := CodexTicketPolicy{TTLSeconds: 3600, RefreshBeforeSeconds: 600, HarvestIntervalSeconds: 20, MaxConsecutiveFailures: 30}
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
