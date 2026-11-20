package service

import (
	"context"
	"fmt"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
)

// OpenAIImagePriorityAccounts 是图片优先账号配置的管理视图。
// AccountIDs 为配置原文（可能含已删除账号），Accounts 为其中仍存在的账号，按配置顺序排列。
type OpenAIImagePriorityAccounts struct {
	AccountIDs []int64
	Accounts   []*Account
}

func (s *adminServiceImpl) GetOpenAIImagePriorityAccounts(ctx context.Context) (*OpenAIImagePriorityAccounts, error) {
	if s.settingService == nil {
		return nil, fmt.Errorf("setting service unavailable")
	}
	ids, err := s.settingService.GetOpenAIImagePriorityAccountIDs(ctx)
	if err != nil {
		return nil, err
	}
	accounts, err := s.loadAccountsInOrder(ctx, ids)
	if err != nil {
		return nil, err
	}
	return &OpenAIImagePriorityAccounts{AccountIDs: ids, Accounts: accounts}, nil
}

func (s *adminServiceImpl) UpdateOpenAIImagePriorityAccounts(ctx context.Context, ids []int64) (*OpenAIImagePriorityAccounts, error) {
	if s.settingService == nil {
		return nil, fmt.Errorf("setting service unavailable")
	}
	normalized := normalizeOpenAIImagePriorityAccountIDs(ids)
	if len(normalized) > MaxOpenAIImagePriorityAccounts {
		return nil, infraerrors.BadRequest("OPENAI_IMAGE_PRIORITY_TOO_MANY_ACCOUNTS",
			fmt.Sprintf("at most %d image priority accounts are allowed", MaxOpenAIImagePriorityAccounts))
	}
	accounts, err := s.loadAccountsInOrder(ctx, normalized)
	if err != nil {
		return nil, err
	}
	found := make(map[int64]*Account, len(accounts))
	for _, account := range accounts {
		found[account.ID] = account
	}
	for _, id := range normalized {
		account, ok := found[id]
		if !ok {
			return nil, infraerrors.BadRequest("OPENAI_IMAGE_PRIORITY_ACCOUNT_NOT_FOUND",
				fmt.Sprintf("account %d not found", id))
		}
		if !account.IsOpenAI() {
			return nil, infraerrors.BadRequest("OPENAI_IMAGE_PRIORITY_ACCOUNT_NOT_OPENAI",
				fmt.Sprintf("account %d is not an OpenAI account", id))
		}
	}
	saved, err := s.settingService.SetOpenAIImagePriorityAccountIDs(ctx, normalized)
	if err != nil {
		return nil, err
	}
	return &OpenAIImagePriorityAccounts{AccountIDs: saved, Accounts: accounts}, nil
}

// loadAccountsInOrder 按 ids 顺序返回仍存在的账号。
func (s *adminServiceImpl) loadAccountsInOrder(ctx context.Context, ids []int64) ([]*Account, error) {
	if len(ids) == 0 {
		return []*Account{}, nil
	}
	accounts, err := s.accountRepo.GetByIDs(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("failed to get accounts by IDs: %w", err)
	}
	byID := make(map[int64]*Account, len(accounts))
	for _, account := range accounts {
		if account != nil {
			byID[account.ID] = account
		}
	}
	ordered := make([]*Account, 0, len(byID))
	for _, id := range ids {
		if account, ok := byID[id]; ok {
			ordered = append(ordered, account)
		}
	}
	return ordered, nil
}
