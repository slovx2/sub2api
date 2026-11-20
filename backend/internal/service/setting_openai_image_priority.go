package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// openAIImagePriorityAccountIDsCacheTTL 控制多实例下设置生效的最长延迟；本实例保存时直接刷新缓存。
const openAIImagePriorityAccountIDsCacheTTL = 10 * time.Second

// MaxOpenAIImagePriorityAccounts 限制图片优先账号数量，避免每次生图调度读取过多账号。
const MaxOpenAIImagePriorityAccounts = 100

type cachedOpenAIImagePriorityAccountIDs struct {
	ids       []int64
	expiresAt time.Time
}

// normalizeOpenAIImagePriorityAccountIDs 去重并丢弃非正数 ID，保留管理员给出的顺序。
func normalizeOpenAIImagePriorityAccountIDs(ids []int64) []int64 {
	result := make([]int64, 0, len(ids))
	seen := make(map[int64]struct{}, len(ids))
	for _, id := range ids {
		if id <= 0 {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		result = append(result, id)
	}
	return result
}

func parseOpenAIImagePriorityAccountIDs(raw string) []int64 {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return []int64{}
	}
	var ids []int64
	if err := json.Unmarshal([]byte(raw), &ids); err != nil {
		return []int64{}
	}
	return normalizeOpenAIImagePriorityAccountIDs(ids)
}

func (s *SettingService) storeOpenAIImagePriorityAccountIDsCache(ids []int64) {
	cached := make([]int64, len(ids))
	copy(cached, ids)
	s.openAIImagePriorityAccountsCache.Store(&cachedOpenAIImagePriorityAccountIDs{
		ids:       cached,
		expiresAt: time.Now().Add(openAIImagePriorityAccountIDsCacheTTL),
	})
}

// GetOpenAIImagePriorityAccountIDs 返回图片优先 OpenAI 账号 ID（按配置顺序）。
// 位于 /v1/images 调度热路径：命中缓存不访问 DB；DB 读取失败时沿用过期缓存，
// 没有缓存则返回错误，由调用方回退到常规调度。
func (s *SettingService) GetOpenAIImagePriorityAccountIDs(ctx context.Context) ([]int64, error) {
	if s == nil || s.settingRepo == nil {
		return []int64{}, nil
	}
	cached, _ := s.openAIImagePriorityAccountsCache.Load().(*cachedOpenAIImagePriorityAccountIDs)
	if cached != nil && time.Now().Before(cached.expiresAt) {
		return append([]int64(nil), cached.ids...), nil
	}

	dbCtx, cancel := context.WithTimeout(ctx, gatewayForwardingDBTimeout)
	defer cancel()
	value, err := s.settingRepo.GetValue(dbCtx, SettingKeyOpenAIImagePriorityAccountIDs)
	if err != nil && !errors.Is(err, ErrSettingNotFound) {
		if cached != nil {
			return append([]int64(nil), cached.ids...), nil
		}
		return nil, fmt.Errorf("get OpenAI image priority account ids: %w", err)
	}
	ids := []int64{}
	if err == nil {
		ids = parseOpenAIImagePriorityAccountIDs(value)
	}
	s.storeOpenAIImagePriorityAccountIDsCache(ids)
	return ids, nil
}

// SetOpenAIImagePriorityAccountIDs 保存图片优先账号 ID 列表。账号存在性与平台校验由调用方
// （AdminService）完成，这里只做规范化和数量上限检查。
func (s *SettingService) SetOpenAIImagePriorityAccountIDs(ctx context.Context, ids []int64) ([]int64, error) {
	if s == nil || s.settingRepo == nil {
		return nil, fmt.Errorf("setting service unavailable")
	}
	normalized := normalizeOpenAIImagePriorityAccountIDs(ids)
	if len(normalized) > MaxOpenAIImagePriorityAccounts {
		return nil, fmt.Errorf("at most %d image priority accounts are allowed", MaxOpenAIImagePriorityAccounts)
	}
	data, err := json.Marshal(normalized)
	if err != nil {
		return nil, fmt.Errorf("marshal OpenAI image priority account ids: %w", err)
	}
	if err := s.settingRepo.Set(ctx, SettingKeyOpenAIImagePriorityAccountIDs, string(data)); err != nil {
		return nil, err
	}
	s.storeOpenAIImagePriorityAccountIDsCache(normalized)
	return normalized, nil
}
