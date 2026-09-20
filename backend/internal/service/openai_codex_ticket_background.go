package service

import (
	"context"
	"sync"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/logger"
	"go.uber.org/zap"
)

func (s *OpenAIGatewayService) StartOpenAICodexTicketHarvester() {
	if s == nil {
		return
	}
	s.openaiCodexTicketLifecycleMu.Lock()
	defer s.openaiCodexTicketLifecycleMu.Unlock()
	if s.openaiCodexTicketStopped || s.openaiCodexTicketBackgroundDone != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.openaiCodexTicketBackgroundCancel = cancel
	done := make(chan struct{})
	s.openaiCodexTicketBackgroundDone = done
	go func() {
		defer close(done)
		s.openAICodexTicketHarvestLoop(ctx)
	}()
}

func (s *OpenAIGatewayService) openAICodexTicketHarvestLoop(ctx context.Context) {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			policy := s.codexTicketPolicy(ctx)
			s.refreshOpenAICodexTicketsWithPolicy(ctx, policy)
			timer.Reset(time.Duration(policy.HarvestIntervalSeconds) * time.Second)
		}
	}
}

func (s *OpenAIGatewayService) refreshOpenAICodexTickets(ctx context.Context) {
	s.refreshOpenAICodexTicketsWithPolicy(ctx, s.codexTicketPolicy(ctx))
}

func (s *OpenAIGatewayService) refreshOpenAICodexTicketsWithPolicy(ctx context.Context, policy CodexTicketPolicy) {
	if s == nil || s.accountRepo == nil || ctx.Err() != nil || !s.openAICodexTicketEnabledContext(ctx) {
		return
	}
	// 标错写库重试不依赖采票代理和传输配置，也不发起上游请求。
	s.retryCodexTicketErrors(ctx)
	if s.httpUpstream == nil || s.openAICodexTicketHarvestProxyURLContext(ctx) == "" {
		return
	}
	readCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	accounts, err := s.accountRepo.ListByPlatform(readCtx, PlatformOpenAI)
	cancel()
	if err != nil {
		if ctx.Err() == nil {
			logger.L().Warn("openai_codex_ticket list accounts failed", zap.Error(err))
		}
		return
	}
	models := s.openAICodexTicketConfig().Models
	var wg sync.WaitGroup
	for _, account := range accounts {
		if ctx.Err() != nil {
			break
		}
		if account.Status != StatusActive || !account.Schedulable || !s.codexTicketAccountSelected(ctx, &account) || s.codexTicketErrorActive(&account) || accountPersistedSchedulingCooldownActive(&account) {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			seen := make(map[string]bool, len(models))
			for _, model := range models {
				model = normalizeOpenAICodexTicketModel(model)
				if model == "" || seen[model] {
					continue
				}
				seen[model] = true
				if ctx.Err() != nil || !s.openAICodexTicketEnabledContext(ctx) || !s.codexTicketAccountSelected(ctx, &account) {
					return
				}
				// 同账号不同模型串行；单模型失败未达阈值时仍检查后续模型。
				_, _ = s.harvestOpenAICodexTicket(ctx, &account, model, policy)
				if s.codexTicketErrorActive(&account) {
					return
				}
			}
		}()
	}
	wg.Wait()
}
