package service

import (
	"context"
	"sync"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/logger"
	"go.uber.org/zap"
)

// 每轮结束后检查一次；有效票和冷却账号不会产生采票请求。
const codexTicketBackgroundInterval = 6 * time.Second

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
			s.refreshOpenAICodexTickets(ctx)
			timer.Reset(codexTicketBackgroundInterval)
		}
	}
}

func (s *OpenAIGatewayService) refreshOpenAICodexTickets(ctx context.Context) {
	if s == nil || s.accountRepo == nil || s.httpUpstream == nil || ctx.Err() != nil || !s.openAICodexTicketEnabledContext(ctx) || s.openAICodexTicketHarvestProxyURLContext(ctx) == "" {
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
		if account.Status != StatusActive || !account.Schedulable || !s.codexTicketAccountSelected(ctx, &account) || s.codexTicketCooldownActive(&account) || accountPersistedSchedulingCooldownActive(&account) {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, model := range models {
				model = normalizeOpenAICodexTicketModel(model)
				if model == "" {
					continue
				}
				if ctx.Err() != nil || !s.openAICodexTicketEnabledContext(ctx) || !s.codexTicketAccountSelected(ctx, &account) {
					return
				}
				// 与业务请求共用账号级协调器：同模型共享重试轮次，不同模型串行。
				// 协调器复用有效票，并在尝试耗尽时记录日志及冷却。
				if _, err := s.ensureOpenAICodexTicket(ctx, &account, model); err != nil {
					return
				}
			}
		}()
	}
	wg.Wait()
}
