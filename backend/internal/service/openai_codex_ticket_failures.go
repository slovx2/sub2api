package service

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// 计数仅保存在本实例；pending 即使写库失败也持续阻止调度，直到人工恢复。
type codexTicketFailureState struct {
	mu      sync.Mutex
	counts  map[string]int
	epoch   uint64
	pending *codexTicketAccountError
	blocked atomic.Bool
}

type codexTicketAccountError struct {
	model     string
	count     int
	reason    string
	persisted bool
}

func (s *OpenAIGatewayService) codexTicketFailureState(id int64) *codexTicketFailureState {
	v, _ := s.openaiCodexTicketFailures.LoadOrStore(id, &codexTicketFailureState{counts: make(map[string]int)})
	state, _ := v.(*codexTicketFailureState)
	return state
}

func (s *OpenAIGatewayService) codexTicketErrorActive(account *Account) bool {
	if s == nil || account == nil {
		return false
	}
	v, ok := s.openaiCodexTicketFailures.Load(account.ID)
	if !ok {
		return false
	}
	state, ok := v.(*codexTicketFailureState)
	return ok && state.blocked.Load()
}

// 人工恢复与标错写库互斥。恢复后仍关闭调度，需管理员主动重新开启。
func (s *OpenAIGatewayService) RecoverCodexTicketAccount(ctx context.Context, id int64) error {
	state := s.codexTicketFailureState(id)
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.pending != nil {
		if err := s.accountRepo.SetSchedulable(ctx, id, false); err != nil {
			return err
		}
		if err := s.accountRepo.ClearError(ctx, id); err != nil {
			return err
		}
	}
	state.epoch++
	clear(state.counts)
	state.pending = nil
	state.blocked.Store(false)
	return nil
}

func (s *OpenAIGatewayService) finishCodexTicketHarvest(ctx context.Context, account *Account, model string, policy CodexTicketPolicy, generation, epoch uint64, harvestErr error) {
	state := s.codexTicketFailureState(account.ID)
	state.mu.Lock()
	defer state.mu.Unlock()
	if epoch != state.epoch || ctx.Err() != nil {
		return
	}
	if harvestErr == nil {
		delete(state.counts, model)
		return
	}
	state.counts[model]++
	if state.counts[model] < policy.MaxConsecutiveFailures {
		return
	}
	state.pending = &codexTicketAccountError{model: model, count: state.counts[model], reason: harvestErr.Error()}
	state.blocked.Store(true)
	s.persistCodexTicketError(ctx, account, state.pending, generation)
}

// 调用时持有账号自己的状态锁，人工恢复不会被在途标错覆盖；不同账号互不阻塞。
func (s *OpenAIGatewayService) persistCodexTicketError(ctx context.Context, account *Account, pending *codexTicketAccountError, generation uint64) {
	if pending.persisted || s.accountRepo == nil || ctx.Err() != nil {
		return
	}
	_, currentGeneration := s.codexTicketAccountScope(ctx)
	if generation != currentGeneration || !s.openAICodexTicketEnabledContext(ctx) || !s.codexTicketAccountSelected(ctx, account) {
		return
	}
	writeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	current, err := s.accountRepo.GetByID(writeCtx, account.ID)
	if err == nil && (current == nil || current.Status != StatusActive || !current.Schedulable || !isOpenAICodexTicketAccount(current)) {
		return
	}
	if err == nil {
		message := fmt.Sprintf("codex ticket: model=%s consecutive_failures=%d; %s", pending.model, pending.count, pending.reason)
		err = s.accountRepo.SetError(writeCtx, account.ID, message)
	}
	event := &CodexTicketEvent{AccountID: account.ID, AccountName: account.Name, Model: pending.model, Kind: "account_error", Reason: "consecutive_failures", Attempt: pending.count}
	if err != nil {
		event.Kind, event.Reason = "account_error_write_failed", "error_persist_failed"
	} else {
		pending.persisted = true
	}
	s.recordCodexTicketEvent(ctx, event)
}

func (s *OpenAIGatewayService) retryCodexTicketErrors(ctx context.Context) {
	_, generation := s.codexTicketAccountScope(ctx)
	s.openaiCodexTicketFailures.Range(func(key, value any) bool {
		state, ok := value.(*codexTicketFailureState)
		if !ok {
			return true
		}
		state.mu.Lock()
		defer state.mu.Unlock()
		if state.pending != nil && !state.pending.persisted {
			id, ok := key.(int64)
			if !ok {
				return true
			}
			account := &Account{ID: id, Platform: PlatformOpenAI, Type: AccountTypeOAuth}
			readCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			if current, err := s.accountRepo.GetByID(readCtx, account.ID); err == nil && current != nil {
				account = current
			}
			s.persistCodexTicketError(ctx, account, state.pending, generation)
		}
		return ctx.Err() == nil
	})
}
