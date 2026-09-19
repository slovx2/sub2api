package service

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/logger"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// 所有协调状态由 openaiCodexTicketLifecycleMu 保护；gate 串行化同账号不同模型。
type codexTicketAccountWork struct {
	gate  chan struct{}
	calls map[string]*codexTicketCall
}

type codexTicketCall struct {
	done    chan struct{}
	cancel  context.CancelFunc
	waiters int
	ticket  *openAICodexTicket
	err     error
}

var errCodexTicketScopeChanged = errors.New("codex ticket scope changed or account unavailable")

// 转发为完整计费可能使用脱离取消的上游 context；等票必须仍受原请求控制。
func (s *OpenAIGatewayService) applyOpenAICodexTicketForRequest(ctx context.Context, c *gin.Context, account *Account, model string, headers http.Header) error {
	if c != nil && c.Request != nil {
		ctx = c.Request.Context()
	}
	return s.applyOpenAICodexTicket(ctx, account, model, headers)
}

// 工厂绑定不可变的模型快照，连接池延迟调用时不能读下一轮正在修改的 payload。
func (s *OpenAIGatewayService) codexTicketWSHeadersFactory(account *Account, model string) func(context.Context, http.Header) (http.Header, error) {
	return func(ctx context.Context, headers http.Header) (http.Header, error) {
		if err := s.applyOpenAICodexTicket(ctx, account, model, headers); err != nil {
			return nil, err
		}
		return s.refreshOpenAIAgentIdentityHeaders(ctx, account, headers)
	}
}

func (s *OpenAIGatewayService) codexTicketPolicy(ctx context.Context) CodexTicketPolicy {
	if s.settingService != nil {
		return s.settingService.GetOpenAICodexTicketPolicy(ctx)
	}
	return (&SettingService{cfg: s.cfg}).codexTicketPolicyFallback()
}

func codexTicketFailover() error {
	return fmt.Errorf("%w: %w", ErrOpenAICodexTicketUnavailable, &UpstreamFailoverError{
		StatusCode:   http.StatusServiceUnavailable,
		ResponseBody: []byte(`{"error":{"type":"upstream_error","message":"Codex ticket unavailable"}}`),
		Reason:       GatewayFailureReason("codex_ticket_unavailable"),
	})
}

func (s *OpenAIGatewayService) ensureOpenAICodexTicket(ctx context.Context, account *Account, model string) (*openAICodexTicket, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if account.Status != StatusActive || !account.Schedulable || s.codexTicketCooldownActive(account) || accountPersistedSchedulingCooldownActive(account) {
		return nil, codexTicketFailover()
	}
	policy := s.codexTicketPolicy(ctx)
	cfg := s.openAICodexTicketConfig()
	s.openaiCodexTicketLifecycleMu.Lock()
	if s.openaiCodexTicketStopped {
		s.openaiCodexTicketLifecycleMu.Unlock()
		return nil, context.Canceled
	}
	if s.openaiCodexTicketAccounts == nil {
		s.openaiCodexTicketAccounts = make(map[int64]*codexTicketAccountWork)
	}
	work := s.openaiCodexTicketAccounts[account.ID]
	if work == nil {
		work = &codexTicketAccountWork{gate: make(chan struct{}, 1), calls: make(map[string]*codexTicketCall)}
		s.openaiCodexTicketAccounts[account.ID] = work
	}
	call := work.calls[model]
	// 有在途采票时必须共享其最终结果，不能提前读取刚写入但尚未完成范围复核的票。
	if call == nil && len(work.gate) == 0 {
		if ticket := s.lookupOpenAICodexTicket(account, model); ticket.valid(time.Now(), cfg.TargetLength) && !ticket.needsRefresh(time.Now(), time.Duration(policy.RefreshBeforeSeconds)*time.Second) {
			s.openaiCodexTicketLifecycleMu.Unlock()
			return ticket, nil
		}
	}
	if call == nil {
		// 不继承首个等待者的取消和截止时间。每次探测有超时，所有等待者退出时主动取消。
		sharedCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
		call = &codexTicketCall{done: make(chan struct{}), cancel: cancel}
		work.calls[model] = call
		acc := *account
		acc.Extra, acc.Credentials = maps.Clone(account.Extra), maps.Clone(account.Credentials)
		s.openaiCodexTicketWorkers.Add(1)
		go s.runCodexTicketCall(sharedCtx, &acc, model, work, call, policy, cfg)
	}
	call.waiters++
	s.openaiCodexTicketLifecycleMu.Unlock()
	defer func() {
		s.openaiCodexTicketLifecycleMu.Lock()
		defer s.openaiCodexTicketLifecycleMu.Unlock()
		call.waiters--
		if call.waiters == 0 {
			call.cancel()
			// 在旧工作完全退出前仍保留账号 gate，不能与下一轮并行。
			if work.calls[model] == call {
				delete(work.calls, model)
			}
		}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-call.done:
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !s.codexTicketAccountSelected(ctx, account) || !s.openAICodexTicketEnabledContext(ctx) {
			return nil, nil
		}
		if call.err != nil {
			return nil, call.err
		}
		return call.ticket, nil
	}
}

func (s *OpenAIGatewayService) runCodexTicketCall(ctx context.Context, account *Account, model string, work *codexTicketAccountWork, call *codexTicketCall, policy CodexTicketPolicy, cfg config.OpenAICodexTicketConfig) {
	defer s.openaiCodexTicketWorkers.Done()
	defer call.cancel()
	defer close(call.done)
	select {
	case <-ctx.Done():
		call.err = ctx.Err()
		return
	case work.gate <- struct{}{}:
	}
	defer func() { <-work.gate }()
	if s.codexTicketCooldownActive(account) {
		call.err = codexTicketFailover()
		return
	}
	// 排队期间其他请求可能已补齐票据；在串行区再次检查。
	if ticket := s.lookupOpenAICodexTicket(account, model); ticket.valid(time.Now(), cfg.TargetLength) && !ticket.needsRefresh(time.Now(), time.Duration(policy.RefreshBeforeSeconds)*time.Second) {
		call.ticket = ticket
		return
	}
	_, generation := s.codexTicketAccountScope(ctx)
	for attempt := 1; attempt <= policy.MaxAttempts; attempt++ {
		if err := s.checkCodexTicketRequestAccount(ctx, account, generation); err != nil {
			call.err = codexTicketFailover()
			return
		}
		ticket, err := s.probeOpenAICodexTicketAttempt(ctx, account, model, policy, cfg, generation, attempt)
		if err == nil {
			call.ticket = ticket
			return
		}
		if ctx.Err() != nil || errors.Is(err, errCodexTicketScopeChanged) {
			call.err = codexTicketFailover()
			return
		}
	}
	if err := s.checkCodexTicketRequestAccount(ctx, account, generation); err == nil {
		s.cooldownCodexTicketAccount(ctx, account, model, policy)
	}
	call.err = codexTicketFailover()
}

// 每次探测前、落票前均读账号真值，不允许关闭调度、停用或删除后的票据重新生效。
func (s *OpenAIGatewayService) checkCodexTicketRequestAccount(ctx context.Context, account *Account, generation uint64) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	_, currentGeneration := s.codexTicketAccountScope(ctx)
	if generation != currentGeneration || !s.codexTicketAccountSelected(ctx, account) || !s.openAICodexTicketEnabledContext(ctx) {
		return errCodexTicketScopeChanged
	}
	current := account
	if s.accountRepo != nil {
		readCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		var err error
		current, err = s.accountRepo.GetByID(readCtx, account.ID)
		if err != nil || current == nil {
			return errCodexTicketScopeChanged
		}
	}
	if current.Status != StatusActive || !current.Schedulable || !isOpenAICodexTicketAccount(current) || accountPersistedSchedulingCooldownActive(current) || s.codexTicketCooldownActive(current) {
		return errCodexTicketScopeChanged
	}
	return nil
}

// 关闭时同时取消自动采票循环及所有共享采票任务，等待其退出。
func (s *OpenAIGatewayService) StopOpenAICodexTicketRequests() {
	if s == nil {
		return
	}
	s.openaiCodexTicketLifecycleMu.Lock()
	s.openaiCodexTicketStopped = true
	cancel, done := s.openaiCodexTicketBackgroundCancel, s.openaiCodexTicketBackgroundDone
	if cancel != nil {
		cancel()
	}
	for _, work := range s.openaiCodexTicketAccounts {
		for _, call := range work.calls {
			call.cancel()
		}
	}
	s.openaiCodexTicketLifecycleMu.Unlock()
	if done != nil {
		<-done
	}
	s.openaiCodexTicketWorkers.Wait()
}

func (s *OpenAIGatewayService) probeOpenAICodexTicketAttempt(ctx context.Context, account *Account, model string, policy CodexTicketPolicy, cfg config.OpenAICodexTicketConfig, generation uint64, attempt int) (*openAICodexTicket, error) {
	event := &CodexTicketEvent{AccountID: account.ID, AccountName: account.Name, Model: model, Kind: "harvest", Reason: "token_error", Attempt: attempt, CreatedAt: time.Now()}
	defer func() { s.recordCodexTicketEvent(ctx, event) }()
	attemptCtx, cancel := context.WithTimeout(ctx, time.Duration(cfg.HarvestAttemptTimeoutSeconds)*time.Second)
	defer cancel()
	proxyURL := s.openAICodexTicketHarvestProxyURLContext(attemptCtx)
	if proxyURL == "" || s.httpUpstream == nil {
		event.Reason = "harvest_not_configured"
		return nil, ErrOpenAICodexTicketUnavailable
	}
	token, _, err := s.GetAccessToken(attemptCtx, account)
	if err != nil || strings.TrimSpace(token) == "" {
		return nil, ErrOpenAICodexTicketUnavailable
	}
	state, status, err := s.fireOpenAICodexTicketProbe(attemptCtx, account, token, model, proxyURL, time.Duration(cfg.HarvestAttemptTimeoutSeconds)*time.Second)
	event.HTTPStatus, event.Length = status, len(state)
	switch {
	case ctx.Err() != nil:
		event.Reason = "scope_changed_or_cancelled"
	case err != nil:
		event.Reason = "request_error"
	case status != http.StatusOK:
		event.Reason = "http_error"
	case state == "":
		event.Reason = "missing_state"
	case !acceptedCodexTicketLength(len(state), cfg.TargetLength):
		event.Reason = "invalid_length"
	case !strings.HasPrefix(state, openAICodexTicketStatePrefix):
		event.Reason = "invalid_format"
	default:
		if err := s.checkCodexTicketRequestAccount(ctx, account, generation); err != nil {
			event.Reason = "scope_changed_or_cancelled"
			return nil, err
		}
		now := time.Now()
		ticket := &openAICodexTicket{AccountID: account.ID, Model: model, State: state, Length: len(state), CapturedAt: now, ExpiresAt: now.Add(time.Duration(policy.TTLSeconds) * time.Second), Attempts: attempt}
		persistErr := s.persistOpenAICodexTicket(ctx, account, ticket)
		// 数据库写入也可能跨越取消选择、停用或请求取消；复核后才能发布给等待者。
		commitErr := s.checkCodexTicketRequestAccount(ctx, account, generation)
		if commitErr == nil {
			commitErr = s.publishCodexTicket(ctx, ticket, generation)
		}
		if commitErr != nil {
			event.Reason = "scope_changed_or_cancelled"
			if persistErr == nil && s.accountRepo != nil {
				cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
				defer cleanupCancel()
				if clearErr := s.accountRepo.UpdateExtra(cleanupCtx, account.ID, map[string]any{openAICodexTicketExtraKey(model): nil}); clearErr != nil {
					logger.L().Warn("codex ticket discard persistence failed", zap.Int64("account_id", account.ID), zap.Error(clearErr))
				}
			}
			return nil, commitErr
		}
		event.Success, event.Reason = true, "accepted"
		return ticket, nil
	}
	return nil, ErrOpenAICodexTicketUnavailable
}

func (s *OpenAIGatewayService) publishCodexTicket(ctx context.Context, ticket *openAICodexTicket, generation uint64) error {
	if settings := s.settingService; settings != nil {
		settings.openAICodexTicketAccountsMu.Lock()
		defer settings.openAICodexTicketAccountsMu.Unlock()
		if scope := settings.openAICodexTicketAccounts; scope == nil || scope.generation != generation {
			return errCodexTicketScopeChanged
		}
	}
	s.openaiCodexTicketLifecycleMu.Lock()
	defer s.openaiCodexTicketLifecycleMu.Unlock()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	s.openaiCodexTickets.Store(openAICodexTicketKey(ticket.AccountID, ticket.Model), ticket)
	return nil
}

func (s *OpenAIGatewayService) codexTicketCooldownActive(account *Account) bool {
	if s == nil || account == nil {
		return false
	}
	_, active := s.codexTicketCooldownUntil(account.ID)
	return active
}

func (s *OpenAIGatewayService) codexTicketCooldownUntil(accountID int64) (time.Time, bool) {
	value, ok := s.openaiCodexTicketCooldowns.Load(accountID)
	if !ok {
		return time.Time{}, false
	}
	until, ok := value.(time.Time)
	if !ok {
		return time.Time{}, false
	}
	if time.Now().Before(until) {
		return until, true
	}
	s.openaiCodexTicketCooldowns.CompareAndDelete(accountID, value)
	return time.Time{}, false
}

func (s *OpenAIGatewayService) cooldownCodexTicketAccount(ctx context.Context, account *Account, model string, policy CodexTicketPolicy) {
	if ctx.Err() != nil {
		return
	}
	until := time.Now().Add(time.Duration(policy.FailureCooldownSeconds) * time.Second)
	if account.TempUnschedulableUntil != nil && account.TempUnschedulableUntil.After(until) {
		until = *account.TempUnschedulableUntil
	}
	// 独立的本地冷却不能被旧调度快照清除。管理员恢复通过 ClearAccountSchedulingBlock 清理。
	s.openaiCodexTicketCooldowns.Store(account.ID, until)
	s.BlockAccountScheduling(account, until, "codex_ticket_failed")
	reason := "codex ticket attempts exhausted"
	event := &CodexTicketEvent{AccountID: account.ID, AccountName: account.Name, Model: model, Kind: "cooldown", Reason: "attempts_exhausted", Attempt: policy.MaxAttempts}
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if s.accountRepo == nil {
		event.Reason = "cooldown_persist_failed"
	} else if err := s.accountRepo.SetTempUnschedulable(writeCtx, account.ID, until, reason); err != nil {
		event.Reason = "cooldown_persist_failed"
	}
	s.recordCodexTicketEvent(writeCtx, event)
}
