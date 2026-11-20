package service

import (
	"context"
	"log/slog"
	"sort"
)

// openAIAccountScheduleLayerImagePriority 标记 /v1/images 请求命中了全局图片优先账号。
const openAIAccountScheduleLayerImagePriority = "image_priority"

type openAIImagePriorityCandidate struct {
	account  *Account
	order    int
	loadRate int
}

// selectOpenAIImagePriorityAccount 在常规调度之前尝试全局图片优先账号。
//
// 与常规调度的差异：
//   - 不要求账号属于 API Key 所在分组（全局生效）；
//   - 忽略管理员手动的 Schedulable 开关，关闭调度的账号同样可承接生图；
//   - 仍然排除 status 非 active、过期、过载、限流（含模型级/生图冷却）、临时不可调度、
//     额度耗尽、代理熔断等状态异常的账号，并遵守分组隐私要求、模型白名单、渠道限制与图片能力。
//
// 返回 nil 表示没有可用的优先账号（未配置、都不可用或并发已满），调用方继续走常规调度。
func (s *OpenAIGatewayService) selectOpenAIImagePriorityAccount(
	ctx context.Context,
	groupID *int64,
	requestedModel string,
	excludedIDs map[int64]struct{},
	requiredImageCapability OpenAIImagesCapability,
) (*AccountSelectionResult, OpenAIAccountScheduleDecision) {
	decision := OpenAIAccountScheduleDecision{Layer: openAIAccountScheduleLayerImagePriority}
	if s == nil || s.settingService == nil || s.accountRepo == nil {
		return nil, decision
	}
	ids, err := s.settingService.GetOpenAIImagePriorityAccountIDs(ctx)
	if err != nil {
		slog.Warn("openai.images.priority_accounts_setting_unavailable", "error", err)
		return nil, decision
	}
	ids = filterOutExcludedAccountIDs(ids, excludedIDs)
	if len(ids) == 0 {
		return nil, decision
	}

	ctx = s.withOpenAIQuotaAutoPauseContext(ctx)
	ctx = s.withOpenAIGroupPrivacyRequirement(ctx, groupID)
	if s.checkChannelPricingRestriction(ctx, groupID, requestedModel) {
		// 渠道定价限制是请求级拦截，交给常规调度返回统一错误。
		return nil, decision
	}

	accounts, err := s.accountRepo.GetByIDs(ctx, ids)
	if err != nil {
		slog.Warn("openai.images.priority_accounts_load_failed", "error", err)
		return nil, decision
	}
	orderByID := make(map[int64]int, len(ids))
	for i, id := range ids {
		orderByID[id] = i
	}

	scheduler := &defaultOpenAIAccountScheduler{service: s}
	req := OpenAIAccountScheduleRequest{
		GroupID:                 groupID,
		Platform:                PlatformOpenAI,
		RequestedModel:          requestedModel,
		RequiredTransport:       OpenAIUpstreamTransportHTTPSSE,
		RequiredImageCapability: requiredImageCapability,
		ExcludedIDs:             excludedIDs,
		RequirePrivacySet:       s.openAIGroupRequiresPrivacySet(ctx, groupID),
	}
	candidates := make([]openAIImagePriorityCandidate, 0, len(accounts))
	skipped := make(map[string]int)
	for _, account := range accounts {
		if account == nil {
			continue
		}
		if reason := s.openAIImagePriorityAccountRejectReason(ctx, scheduler, account, req); reason != "" {
			skipped[reason]++
			continue
		}
		candidates = append(candidates, openAIImagePriorityCandidate{account: account, order: orderByID[account.ID]})
	}
	decision.CandidateCount = len(candidates)
	if len(candidates) == 0 {
		slog.Debug("openai.images.priority_accounts_unavailable", "configured", len(ids), "skipped", skipped)
		return nil, decision
	}

	s.fillOpenAIImagePriorityLoadRates(ctx, candidates)
	sortOpenAIImagePriorityCandidates(candidates)

	for _, candidate := range candidates {
		result, err := s.tryAcquireAccountSlot(ctx, candidate.account.ID, candidate.account.Concurrency)
		if err != nil {
			slog.Warn("openai.images.priority_account_acquire_failed", "account_id", candidate.account.ID, "error", err)
			continue
		}
		if result == nil || !result.Acquired {
			continue
		}
		decision.SelectedAccountID = candidate.account.ID
		decision.SelectedAccountType = candidate.account.Type
		return &AccountSelectionResult{
			Account:     candidate.account,
			Acquired:    true,
			ReleaseFunc: result.ReleaseFunc,
		}, decision
	}
	// 优先账号并发均已满：不排队等待，直接回退常规调度。
	return nil, decision
}

// openAIImagePriorityAccountRejectReason 返回优先账号不可用的原因，空串表示可用。
func (s *OpenAIGatewayService) openAIImagePriorityAccountRejectReason(
	ctx context.Context,
	scheduler *defaultOpenAIAccountScheduler,
	account *Account,
	req OpenAIAccountScheduleRequest,
) string {
	if !account.IsOpenAI() {
		return "platform_mismatch"
	}
	if !account.IsSchedulableIgnoringManualSwitch() {
		return "status_unavailable"
	}
	if account.isModelRateLimitedWithContext(ctx, req.RequestedModel) {
		return "model_rate_limited"
	}
	if s.isOpenAIAccountBlockedBySchedulingThreshold(ctx, account) {
		return "scheduling_threshold"
	}
	if ok, reason := scheduler.isAccountRequestCompatibleReason(ctx, account, req); !ok {
		return reason
	}
	return ""
}

func (s *OpenAIGatewayService) fillOpenAIImagePriorityLoadRates(ctx context.Context, candidates []openAIImagePriorityCandidate) {
	if s.concurrencyService == nil || len(candidates) < 2 {
		return
	}
	accounts := make([]*Account, 0, len(candidates))
	for _, candidate := range candidates {
		accounts = append(accounts, candidate.account)
	}
	loads, err := s.concurrencyService.GetAccountsLoadBatch(ctx, buildOpenAIAccountLoadRequest(accounts))
	if err != nil {
		return
	}
	for i := range candidates {
		if info, ok := loads[candidates[i].account.ID]; ok && info != nil {
			candidates[i].loadRate = info.LoadRate
		}
	}
}

// sortOpenAIImagePriorityCandidates 按账号优先级（数值小优先）、负载率、配置顺序排序。
func sortOpenAIImagePriorityCandidates(candidates []openAIImagePriorityCandidate) {
	sort.SliceStable(candidates, func(i, j int) bool {
		left, right := candidates[i], candidates[j]
		if left.account.Priority != right.account.Priority {
			return left.account.Priority < right.account.Priority
		}
		if left.loadRate != right.loadRate {
			return left.loadRate < right.loadRate
		}
		return left.order < right.order
	})
}

func filterOutExcludedAccountIDs(ids []int64, excludedIDs map[int64]struct{}) []int64 {
	if len(excludedIDs) == 0 {
		return ids
	}
	result := make([]int64, 0, len(ids))
	for _, id := range ids {
		if _, excluded := excludedIDs[id]; !excluded {
			result = append(result, id)
		}
	}
	return result
}
