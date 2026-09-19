package service

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"
)

const SettingKeyOpenAICodexTicketAccountIDs = "openai_codex_ticket_account_ids"

type cachedCodexTicketAccounts struct {
	ids        []int64
	expiresAt  time.Time
	generation uint64
}

func normalizeCodexTicketAccountIDs(ids []int64) ([]int64, error) {
	out := append([]int64{}, ids...)
	for _, id := range out {
		if id <= 0 {
			return nil, errors.New("打票账号 ID 必须为正整数")
		}
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

func parseCodexTicketAccountIDs(raw string, fallback []int64) []int64 {
	if strings.TrimSpace(raw) == "" {
		return append([]int64{}, fallback...)
	}
	var ids []int64
	if json.Unmarshal([]byte(raw), &ids) != nil || strings.TrimSpace(raw) == "null" {
		// 损坏的范围不能被解释成全部账号。
		return []int64{-1}
	}
	ids, err := normalizeCodexTicketAccountIDs(ids)
	if err != nil {
		return []int64{-1}
	}
	return ids
}

func (s *SettingService) codexTicketAccountFallback() []int64 {
	if s != nil && s.cfg != nil {
		return s.cfg.Gateway.OpenAICodexTicket.AccountIDs
	}
	return nil
}

// 快照同时用于采票、调度、注入和展示；读取失败不扩大已有范围。
func (s *SettingService) codexTicketAccountsSnapshot(ctx context.Context) ([]int64, uint64) {
	if s == nil {
		return nil, 0
	}
	s.openAICodexTicketAccountsMu.Lock()
	defer s.openAICodexTicketAccountsMu.Unlock()
	previous := s.openAICodexTicketAccounts
	if previous != nil && time.Now().Before(previous.expiresAt) {
		return slices.Clone(previous.ids), previous.generation
	}
	ids := append([]int64{}, s.codexTicketAccountFallback()...)
	generation := uint64(0)
	if previous != nil {
		generation = previous.generation
	}
	if s.settingRepo != nil {
		readCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		raw, err := s.settingRepo.GetValue(readCtx, SettingKeyOpenAICodexTicketAccountIDs)
		switch {
		case err == nil:
			ids = parseCodexTicketAccountIDs(raw, ids)
		case errors.Is(err, ErrSettingNotFound):
		case previous != nil:
			return slices.Clone(previous.ids), generation
		default:
			return []int64{-1}, generation
		}
	}
	if previous == nil || !slices.Equal(previous.ids, ids) {
		generation++
	}
	s.openAICodexTicketAccounts = &cachedCodexTicketAccounts{ids: ids, generation: generation, expiresAt: time.Now().Add(5 * time.Second)}
	return slices.Clone(ids), generation
}

func (s *SettingService) GetOpenAICodexTicketAccountIDs(ctx context.Context) []int64 {
	ids, _ := s.codexTicketAccountsSnapshot(ctx)
	return ids
}

func (s *SettingService) InvalidateOpenAICodexTicketAccountsCache() {
	s.openAICodexTicketAccountsMu.Lock()
	defer s.openAICodexTicketAccountsMu.Unlock()
	if s.openAICodexTicketAccounts != nil {
		s.openAICodexTicketAccounts.expiresAt = time.Time{}
		s.openAICodexTicketAccounts.generation++
	}
}

func codexTicketAccountSelected(ids []int64, accountID int64) bool {
	return len(ids) == 0 || slices.Contains(ids, accountID)
}

func (s *OpenAIGatewayService) codexTicketAccountScope(ctx context.Context) ([]int64, uint64) {
	if s.settingService != nil {
		return s.settingService.codexTicketAccountsSnapshot(ctx)
	}
	return s.openAICodexTicketConfig().AccountIDs, 0
}

func (s *OpenAIGatewayService) codexTicketAccountSelected(ctx context.Context, account *Account) bool {
	if s == nil || !isOpenAICodexTicketAccount(account) {
		return false
	}
	ids, _ := s.codexTicketAccountScope(ctx)
	return codexTicketAccountSelected(ids, account.ID)
}
