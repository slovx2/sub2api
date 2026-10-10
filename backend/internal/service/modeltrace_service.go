package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/modeltrace"
	"github.com/google/uuid"
)

type ModelTraceService struct {
	settings *SettingService
	accounts modelTraceAccounts
	repo     ModelTraceRepository
	caller   modelTraceCaller
	cancel   context.CancelFunc
	done     chan struct{}
	wake     chan struct{}
	once     sync.Once
}

func NewModelTraceService(settings *SettingService, accounts AccountRepository, repo ModelTraceRepository, caller *OpenAIProbeTransport) *ModelTraceService {
	return &ModelTraceService{settings: settings, accounts: accounts, repo: repo, caller: caller, wake: make(chan struct{}, 1)}
}
func (s *ModelTraceService) Start() {
	s.once.Do(func() {
		ctx, cancel := context.WithCancel(context.Background())
		s.cancel = cancel
		s.done = make(chan struct{})
		go func() {
			defer close(s.done)
			maintenanceDone := make(chan struct{})
			go func() { defer close(maintenanceDone); s.maintainHistory(ctx) }()
			s.loop(ctx)
			cancel()
			<-maintenanceDone
		}()
	})
}
func (s *ModelTraceService) Stop() {
	if s.cancel != nil {
		s.cancel()
		<-s.done
	}
}
func (s *ModelTraceService) Wake() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}
func (s *ModelTraceService) Settings(ctx context.Context) (ModelTraceSettings, error) {
	return s.settings.GetModelTraceSettings(ctx)
}

type ModelTraceAccountOption struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

func (s *ModelTraceService) Accounts(ctx context.Context) ([]ModelTraceAccountOption, error) {
	accounts, err := s.accounts.ListAllWithFilters(ctx, PlatformOpenAI, AccountTypeOAuth, "", "", 0, "")
	if err != nil {
		return nil, err
	}
	out := []ModelTraceAccountOption{}
	for i := range accounts {
		if ModelTraceEligible(&accounts[i]) {
			out = append(out, ModelTraceAccountOption{accounts[i].ID, accounts[i].Name})
		}
	}
	return out, nil
}
func (s *ModelTraceService) SaveSettings(ctx context.Context, cfg ModelTraceSettings) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	accounts, err := s.Accounts(ctx)
	if err != nil {
		return err
	}
	eligible := map[int64]bool{}
	for _, a := range accounts {
		eligible[a.ID] = true
	}
	for _, id := range cfg.AccountIDs {
		if !eligible[id] {
			return fmt.Errorf("账号 %d 不是可探测的普通 OpenAI OAuth 账号", id)
		}
	}
	if cfg.Enabled && cfg.AccountMode == "all" && len(accounts) == 0 {
		return fmt.Errorf("没有可探测账号")
	}
	ids := make([]int64, 0, len(accounts))
	for _, account := range accounts {
		ids = append(ids, account.ID)
	}
	if err = s.repo.UpdateSettings(ctx, cfg, ids); err != nil {
		return err
	}
	s.Wake()
	return err
}
func (s *ModelTraceService) RunNow(ctx context.Context) (ModelTraceQueueResult, error) {
	out := ModelTraceQueueResult{}
	cfg, err := s.Settings(ctx)
	if err != nil {
		return out, err
	}
	if !cfg.Enabled {
		return out, fmt.Errorf("请先保存并启用 ModelTrace")
	}
	accounts, err := s.accounts.ListAllWithFilters(ctx, PlatformOpenAI, AccountTypeOAuth, "", "", 0, "")
	if err != nil {
		return out, err
	}
	ids := []int64{}
	for i := range accounts {
		if cfg.Includes(&accounts[i]) {
			ids = append(ids, accounts[i].ID)
		}
	}
	queued, err := s.repo.Enqueue(ctx, ids)
	queued.Unavailable += out.Unavailable
	s.Wake()
	return queued, err
}
func (s *ModelTraceService) Summaries(ctx context.Context, accounts []Account) (map[int64]*ModelTraceSummary, error) {
	out := map[int64]*ModelTraceSummary{}
	cfg, err := s.Settings(ctx)
	if err != nil {
		return nil, err
	}
	if len(cfg.Targets) == 0 {
		return out, nil
	}
	ids := make([]int64, 0, len(accounts))
	for _, a := range accounts {
		if ModelTraceEligible(&a) {
			ids = append(ids, a.ID)
		}
	}
	results, err := s.repo.Latest(ctx, ids)
	if err != nil {
		return nil, err
	}
	states, err := s.repo.States(ctx, ids)
	if err != nil {
		return nil, err
	}
	for i := range accounts {
		a := &accounts[i]
		if cfg.Includes(a) && len(cfg.Targets) > 0 || len(results[a.ID]) > 0 {
			out[a.ID] = modelTraceSummary(cfg, results[a.ID], states[a.ID].Running)
			out[a.ID].AutoSchedule = cfg.autoSchedulesID(a.ID)
		}
	}
	return out, nil
}
func (s *ModelTraceService) loop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		cfg, err := s.Settings(ctx)
		if err == nil && cfg.Enabled {
			lease, acquireErr := s.repo.Acquire(ctx)
			if acquireErr != nil {
				slog.Warn("modeltrace_leader_unavailable")
			}
			if lease != nil {
				s.lead(ctx, lease, cfg)
				lease.Close()
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-s.wake:
		}
	}
}
func modelTraceExecutionKey(cfg ModelTraceSettings) string {
	ids := append([]int64{}, cfg.AccountIDs...)
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	raw, _ := json.Marshal(struct {
		Mode    string
		IDs     []int64
		Targets string
	}{cfg.AccountMode, ids, modelTraceTargetsKey(cfg)})
	return string(raw)
}

func modelTraceTargetsKey(cfg ModelTraceSettings) string {
	keys := make([]string, 0, len(cfg.Targets))
	for _, target := range cfg.Targets {
		keys = append(keys, target.key())
	}
	sort.Strings(keys)
	raw, _ := json.Marshal(keys)
	return string(raw)
}

var errModelTraceConfigChanged = errors.New("探测配置已变化")

func (s *ModelTraceService) lead(parent context.Context, lease ModelTraceLease, initial ModelTraceSettings) {
	ctx, cancel := context.WithCancelCause(parent)
	defer cancel(nil)
	if err := s.repo.Recover(ctx, time.Duration(initial.IntervalMinutes)*time.Minute); err != nil {
		slog.Warn("modeltrace_recover_failed")
		return
	}
	owner := uuid.NewString()
	running := map[int64]context.CancelFunc{}
	done := make(chan int64, 50)
	var wg sync.WaitGroup
	defer func() {
		cancel(nil)
		for _, stop := range running {
			stop()
		}
		wg.Wait()
	}()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	executionKey := modelTraceExecutionKey(initial)
	var accounts []Account
	var refreshedAt time.Time
	for {
		checkCtx, checkCancel := context.WithTimeout(ctx, 3*time.Second)
		err := lease.Check(checkCtx)
		checkCancel()
		if err != nil {
			return
		}
		cfg, err := s.Settings(ctx)
		if err != nil || !cfg.Enabled {
			return
		}
		if key := modelTraceExecutionKey(cfg); key != executionKey {
			cancel(errModelTraceConfigChanged)
			return
		}
		// 全量关联加载最多每分钟一次；显式唤醒立即刷新，新账号自动纳入下一轮。
		if time.Since(refreshedAt) >= time.Minute {
			accounts, err = s.accounts.ListAllWithFilters(ctx, PlatformOpenAI, AccountTypeOAuth, "", "", 0, "")
			if err != nil {
				slog.Warn("modeltrace_accounts_unavailable")
				return
			}
			refreshedAt = time.Now()
		}
		ids := make([]int64, 0, len(accounts))
		for i := range accounts {
			if cfg.Includes(&accounts[i]) {
				ids = append(ids, accounts[i].ID)
			}
		}
		states, err := s.repo.States(ctx, ids)
		if err != nil {
			slog.Warn("modeltrace_states_unavailable")
			return
		}
		for i := range accounts {
			account := accounts[i]
			if !cfg.Includes(&account) {
				continue
			}
			if len(running) >= cfg.Concurrency {
				break
			}
			if _, ok := running[account.ID]; ok {
				continue
			}
			if state := states[account.ID]; state.Running || !state.Requested && state.NextRunAt.After(time.Now()) {
				continue
			}
			claimed, err := s.repo.Claim(ctx, account.ID, owner)
			if err != nil {
				slog.Warn("modeltrace_claim_failed")
				continue
			}
			if !claimed {
				continue
			}
			taskCtx, stop := context.WithCancel(ctx)
			running[account.ID] = stop
			wg.Add(1)
			go func(id int64) { defer wg.Done(); defer func() { done <- id }(); s.runAccount(taskCtx, id, cfg, owner) }(account.ID)
		}
		select {
		case <-ctx.Done():
			return
		case id := <-done:
			if stop := running[id]; stop != nil {
				stop()
				delete(running, id)
			}
		case <-ticker.C:
		case <-s.wake:
			refreshedAt = time.Time{}
		}
	}
}
func (s *ModelTraceService) runAccount(ctx context.Context, id int64, cfg ModelTraceSettings, owner string) {
	defer func() {
		finishCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		delay := time.Duration(cfg.IntervalMinutes) * time.Minute
		if errors.Is(context.Cause(ctx), errModelTraceConfigChanged) {
			delay = 0
		}
		if err := s.repo.Finish(finishCtx, id, owner, delay); err != nil {
			slog.Warn("modeltrace_finish_failed", "account_id", id)
		}
	}()
	round := s.probeTargets(ctx, id, cfg, owner)
	// 配置变化或停用而取消的轮次不改调度；此时账号仍处于 running，与下一轮串行。
	if ctx.Err() == nil {
		s.applyAutoSchedule(ctx, id, round)
	}
}

// probeTargets 顺序探测全部目标，返回本轮已保存的结果；出错或取消时提前结束。
func (s *ModelTraceService) probeTargets(ctx context.Context, id int64, cfg ModelTraceSettings, owner string) []ModelTraceResult {
	var round []ModelTraceResult
	for _, target := range cfg.Targets {
		if ctx.Err() != nil {
			return round
		}
		snapshot, err := s.repo.BeginProbe(ctx, id, target)
		if err != nil {
			slog.Warn("modeltrace_probe_snapshot_failed", "account_id", id)
			return round
		}
		if snapshot == nil {
			continue
		}
		result := s.probe(ctx, id, snapshot.Target)
		if ctx.Err() != nil {
			return round
		}
		if err := s.repo.Save(ctx, result, owner, *snapshot); err != nil {
			slog.Warn("modeltrace_result_save_failed", "account_id", id)
			return round
		}
		round = append(round, result)
	}
	return round
}

// applyAutoSchedule 按本轮结果接管账号的调度开关。开关不参与执行键，
// 因此读取最新配置并按最新预期判定，轮次中途修改预期或增删目标不会误开误关。
func (s *ModelTraceService) applyAutoSchedule(ctx context.Context, id int64, round []ModelTraceResult) {
	cfg, err := s.Settings(ctx)
	if err != nil {
		slog.Warn("modeltrace_auto_schedule_failed", "account_id", id, "error", err)
		return
	}
	if !cfg.autoSchedulesID(id) {
		return
	}
	schedulable := modelTraceAutoSchedule(cfg.Targets, round)
	if schedulable == nil {
		return
	}
	account, err := s.accounts.GetByID(ctx, id)
	if err != nil {
		slog.Warn("modeltrace_auto_schedule_failed", "account_id", id, "error", err)
		return
	}
	if !ModelTraceEligible(account) || account.Schedulable == *schedulable {
		return
	}
	if *schedulable && !modelTraceCanOpen(account, time.Now()) {
		return
	}
	// 写入与调度事件不随轮次取消而中断：状态一致后不会再补发。
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := s.accounts.SetSchedulable(writeCtx, id, *schedulable); err != nil {
		slog.Warn("modeltrace_auto_schedule_failed", "account_id", id, "error", err)
		return
	}
	slog.Info("modeltrace_auto_schedule", "account_id", id, "schedulable", *schedulable)
}
func (s *ModelTraceService) probe(parent context.Context, id int64, target ModelTraceTarget) ModelTraceResult {
	ctx, cancel := context.WithTimeout(parent, 10*time.Minute)
	defer cancel()
	result := ModelTraceResult{AccountID: id, Protocol: target.Protocol, Model: target.Model, Status: "error", BankVersion: modeltrace.Version(), StartedAt: time.Now()}
	outputs := []modeltrace.Output{}
	// 每个目标读取一次最新账号；挑战之间复用只读快照，不介入凭证刷新。
	account, accountErr := s.accounts.GetByID(ctx, id)
	for _, challenge := range modeltrace.Challenges {
		if len(outputs) == 3 || ctx.Err() != nil {
			break
		}
		if accountErr != nil || !ModelTraceEligible(account) {
			result.Error = "账号不可探测"
			break
		}
		requestCtx, stop := context.WithTimeout(ctx, 240*time.Second)
		reply, err := s.caller.Call(requestCtx, account, target.Protocol, target.Model, challenge.Prompt)
		stop()
		result.UpstreamModel = reply.UpstreamModel
		sample := ModelTraceSample{HTTPStatus: reply.Status}
		output := modeltrace.Output{Text: reply.Text, Expected: challenge.Expected}
		if err != nil {
			sample.Error = err.Error()
		} else {
			sample.Diagnostic = modeltrace.Inspect(output)
			if sample.Accepted {
				outputs = append(outputs, output)
			} else {
				sample.Error = "有效数字不足"
			}
		}
		result.Samples = append(result.Samples, sample)
		if sample.Error != "" {
			result.Error = sample.Error
		}
		var credentialError modelTraceCredentialError
		if errors.As(err, &credentialError) || reply.Status == 401 || reply.Status == 403 || reply.Status == 429 {
			break
		}
	}
	if len(outputs) == 3 {
		score, err := modeltrace.Analyze(outputs)
		if err == nil {
			result.Status = "success"
			result.Error = ""
			result.Prediction = score.Model
			result.Probability = score.Probability
			result.Candidates = score.Candidates
		} else {
			result.Error = "指纹评分失败"
		}
	} else if result.Error == "" {
		result.Error = fmt.Sprintf("样本不足：%d/3", len(outputs))
	}
	if ctx.Err() != nil && result.Status != "success" {
		result.Status = "error"
		result.Error = "探测超时或已取消"
	}
	result.FinishedAt = time.Now()
	return result
}
