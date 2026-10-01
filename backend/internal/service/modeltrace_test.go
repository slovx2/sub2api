package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestModelTraceSettingsValidation(t *testing.T) {
	cfg := DefaultModelTraceSettings()
	require.NoError(t, cfg.Validate())
	require.Equal(t, 30, cfg.IntervalMinutes)
	require.Equal(t, 5, cfg.Concurrency)
	cfg.Enabled = true
	require.Error(t, cfg.Validate())
	cfg.AccountMode = "all"
	cfg.Targets = []ModelTraceTarget{{Protocol: "codex", Model: " gpt-6-astra "}}
	require.NoError(t, cfg.Validate())
	require.Equal(t, "gpt-6-astra", cfg.Targets[0].ExpectedModel())
	cfg.Targets[0].Expected = "gpt-5.6-luna"
	require.Equal(t, "gpt-5.6-luna", cfg.Targets[0].ExpectedModel())
	cfg.IntervalMinutes = 9
	require.Error(t, cfg.Validate())
	cfg.IntervalMinutes = 10
	cfg.Concurrency = 51
	require.Error(t, cfg.Validate())
	cfg.Concurrency = 5
	cfg.Targets = append(cfg.Targets, cfg.Targets[0])
	require.Error(t, cfg.Validate())
}
func TestModelTraceSummaryThresholdAndCurrentExpectation(t *testing.T) {
	cfg := DefaultModelTraceSettings()
	cfg.Targets = []ModelTraceTarget{{Protocol: "codex", Model: "requested", Expected: "actual"}}
	result := ModelTraceResult{Protocol: "codex", Model: "requested", Status: "success", Prediction: "actual"}
	for _, probability := range []float64{.899999, .9, .900001, .99} {
		result.Probability = probability
		s := modelTraceSummary(cfg, []ModelTraceResult{result}, false)
		if probability > .9 {
			require.Equal(t, 1, s.Matched)
		} else {
			require.Zero(t, s.Matched)
			require.Zero(t, s.Mismatched)
		}
	}
	cfg.Targets[0].Expected = "different"
	s := modelTraceSummary(cfg, []ModelTraceResult{result}, true)
	require.Equal(t, 1, s.Mismatched)
	require.True(t, s.Running)
	result.Status = "error"
	s = modelTraceSummary(cfg, []ModelTraceResult{result}, false)
	require.Zero(t, s.Mismatched)
	cfg.Targets = nil
	s = modelTraceSummary(cfg, []ModelTraceResult{result}, false)
	require.Empty(t, s.Details)
}
func TestModelTraceAccountEligibility(t *testing.T) {
	account := probeTestAccount()
	require.True(t, ModelTraceEligible(account))
	cfg := DefaultModelTraceSettings()
	cfg.AccountMode = "all"
	require.True(t, cfg.Includes(account))
	account.ID = 999
	require.True(t, cfg.Includes(account))
	account.Type = AccountTypeAPIKey
	require.False(t, ModelTraceEligible(account))
	account.Type = AccountTypeOAuth
	account.Credentials["auth_mode"] = "personal_access_token"
	require.False(t, ModelTraceEligible(account))
}

type modelTraceSettingsStub struct {
	SettingRepository
	mu  sync.Mutex
	raw string
}

func (r *modelTraceSettingsStub) GetValue(context.Context, string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.raw == "" {
		return "", ErrSettingNotFound
	}
	return r.raw, nil
}
func (r *modelTraceSettingsStub) Set(_ context.Context, _ string, value string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.raw = value
	return nil
}

type modelTraceMultiAccounts struct {
	AccountRepository
	mu       sync.Mutex
	lists    atomic.Int32
	gets     atomic.Int32
	accounts []Account
}

func (r *modelTraceMultiAccounts) ListAllWithFilters(context.Context, string, string, string, string, int64, string) ([]Account, error) {
	r.lists.Add(1)
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Account{}, r.accounts...), nil
}
func (r *modelTraceMultiAccounts) GetByID(_ context.Context, id int64) (*Account, error) {
	r.gets.Add(1)
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.accounts {
		if r.accounts[i].ID == id {
			a := r.accounts[i]
			return &a, nil
		}
	}
	return nil, fmt.Errorf("missing")
}

type modelTraceMemoryRepo struct {
	ModelTraceRepository
	settings *SettingService
	mu       sync.Mutex
	states   map[int64]ModelTraceState
	owners   map[int64]string
	saved    []ModelTraceResult
}

func (r *modelTraceMemoryRepo) Recover(context.Context, time.Duration) error { return nil }
func (r *modelTraceMemoryRepo) ClearQueue(context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, state := range r.states {
		state.Requested = false
		r.states[id] = state
	}
	return nil
}
func (r *modelTraceMemoryRepo) States(_ context.Context, ids []int64) (map[int64]ModelTraceState, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := map[int64]ModelTraceState{}
	for _, id := range ids {
		out[id] = r.states[id]
	}
	return out, nil
}
func (r *modelTraceMemoryRepo) Enqueue(_ context.Context, ids []int64) (ModelTraceQueueResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := ModelTraceQueueResult{}
	for _, id := range ids {
		state := r.states[id]
		if state.Running || state.Requested {
			out.Running++
			continue
		}
		state.Requested = true
		r.states[id] = state
		out.Accepted++
	}
	return out, nil
}
func (r *modelTraceMemoryRepo) Reschedule(_ context.Context, ids []int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, id := range ids {
		state := r.states[id]
		state.Requested = true
		r.states[id] = state
	}
	return nil
}
func (r *modelTraceMemoryRepo) Claim(_ context.Context, id int64, owner string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.states[id]
	if ok && (s.Running || !s.Requested && s.NextRunAt.After(time.Now())) {
		return false, nil
	}
	s.Running = true
	s.Requested = false
	r.states[id] = s
	r.owners[id] = owner
	return true, nil
}
func (r *modelTraceMemoryRepo) Save(_ context.Context, result ModelTraceResult, owner string, _ ModelTraceProbeSnapshot) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.owners[result.AccountID] == owner {
		r.saved = append(r.saved, result)
	}
	return nil
}

func (r *modelTraceMemoryRepo) BeginProbe(ctx context.Context, id int64, target ModelTraceTarget) (*ModelTraceProbeSnapshot, error) {
	cfg, err := r.settings.GetModelTraceSettings(ctx)
	if err != nil {
		return nil, err
	}
	target, active := cfg.ActiveTarget(id, target.Protocol, target.Model)
	if !active {
		return nil, nil
	}
	return &ModelTraceProbeSnapshot{Target: target, Generation: 1}, nil
}
func (r *modelTraceMemoryRepo) UpdateSettings(ctx context.Context, cfg ModelTraceSettings, ids []int64) error {
	previous, err := r.settings.GetModelTraceSettings(ctx)
	if err != nil {
		return err
	}
	if err = r.settings.SaveModelTraceSettings(ctx, cfg); err != nil {
		return err
	}
	if !cfg.Enabled {
		return r.ClearQueue(ctx)
	}
	var requested []int64
	for _, id := range ids {
		if cfg.includesID(id) && (!previous.Enabled || !previous.includesID(id) || modelTraceTargetsKey(cfg) != modelTraceTargetsKey(previous)) {
			requested = append(requested, id)
		}
	}
	return r.Reschedule(ctx, requested)
}
func (r *modelTraceMemoryRepo) Finish(_ context.Context, id int64, owner string, interval time.Duration) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.owners[id] == owner {
		r.states[id] = ModelTraceState{Requested: r.states[id].Requested, NextRunAt: time.Now().Add(interval)}
	}
	return nil
}

type modelTraceTestLease struct{}

func (modelTraceTestLease) Check(context.Context) error { return nil }
func (modelTraceTestLease) Close()                      {}

type modelTraceBlockingCaller struct {
	started chan int64
	release chan struct{}
}

func (c *modelTraceBlockingCaller) Call(ctx context.Context, a *Account, _, _, _ string) (ProbeReply, error) {
	select {
	case c.started <- a.ID:
	case <-ctx.Done():
		return ProbeReply{}, ctx.Err()
	}
	select {
	case <-c.release:
		return ProbeReply{Text: strings.Repeat("42 ", 330), Status: 200}, nil
	case <-ctx.Done():
		return ProbeReply{}, ctx.Err()
	}
}
func TestModelTraceRunnerConcurrencyAndCancellation(t *testing.T) {
	settingsRepo := &modelTraceSettingsStub{}
	settings := NewSettingService(settingsRepo, nil)
	cfg := DefaultModelTraceSettings()
	cfg.Enabled = true
	cfg.AccountMode = "all"
	cfg.Targets = []ModelTraceTarget{{Protocol: "codex", Model: "gpt-6-astra"}, {Protocol: "bps", Model: "gpt-6-astra"}}
	require.NoError(t, settings.SaveModelTraceSettings(context.Background(), cfg))
	accounts := &modelTraceMultiAccounts{}
	for i := 1; i <= 7; i++ {
		a := *probeTestAccount()
		a.ID = int64(i)
		accounts.accounts = append(accounts.accounts, a)
	}
	before, _ := json.Marshal(accounts.accounts)
	repo := &modelTraceMemoryRepo{settings: settings, states: map[int64]ModelTraceState{}, owners: map[int64]string{}}
	caller := &modelTraceBlockingCaller{started: make(chan int64, 50), release: make(chan struct{})}
	svc := &ModelTraceService{settings: settings, accounts: accounts, repo: repo, caller: caller, wake: make(chan struct{}, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); svc.lead(ctx, modelTraceTestLease{}, cfg) }()
	seen := map[int64]bool{}
	for i := 0; i < 5; i++ {
		select {
		case id := <-caller.started:
			require.False(t, seen[id])
			seen[id] = true
		case <-time.After(2 * time.Second):
			t.Fatal("未按并发 5 启动")
		}
	}
	select {
	case <-caller.started:
		t.Fatal("超过并发限制或同账号并行")
	case <-time.After(50 * time.Millisecond):
	}
	cfg.Enabled = false
	require.NoError(t, settings.SaveModelTraceSettings(ctx, cfg))
	svc.Wake()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("关闭未取消在途任务")
	}
	repo.mu.Lock()
	require.Empty(t, repo.saved)
	for _, state := range repo.states {
		require.False(t, state.Running)
	}
	repo.mu.Unlock()
	after, _ := json.Marshal(accounts.accounts)
	require.JSONEq(t, string(before), string(after))
}
