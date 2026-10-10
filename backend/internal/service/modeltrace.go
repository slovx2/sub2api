package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/modeltrace"
)

const modelTraceSettingKey = "modeltrace"

type ModelTraceTarget struct {
	Protocol string `json:"protocol"`
	Model    string `json:"model"`
	Expected string `json:"expected_model"`
}

func (t ModelTraceTarget) ExpectedModel() string {
	if t.Expected != "" {
		return t.Expected
	}
	return t.Model
}
func (t ModelTraceTarget) key() string { return t.Protocol + "\x00" + t.Model }

type ModelTraceSettings struct {
	Enabled                bool               `json:"enabled"`
	AccountMode            string             `json:"account_mode"`
	AccountIDs             []int64            `json:"account_ids"`
	AutoScheduleAccountIDs []int64            `json:"auto_schedule_account_ids"`
	Targets                []ModelTraceTarget `json:"targets"`
	IntervalMinutes        int                `json:"interval_minutes"`
	Concurrency            int                `json:"concurrency"`
}

func DefaultModelTraceSettings() ModelTraceSettings {
	return ModelTraceSettings{AccountMode: "selected", AccountIDs: []int64{}, AutoScheduleAccountIDs: []int64{}, Targets: []ModelTraceTarget{}, IntervalMinutes: 30, Concurrency: 5}
}
func (s *ModelTraceSettings) Validate() error {
	if s.AccountIDs == nil {
		s.AccountIDs = []int64{}
	}
	if s.AutoScheduleAccountIDs == nil {
		s.AutoScheduleAccountIDs = []int64{}
	}
	if s.Targets == nil {
		s.Targets = []ModelTraceTarget{}
	}
	if s.AccountMode == "all" {
		s.AccountIDs = []int64{}
	}

	if s.AccountMode != "all" && s.AccountMode != "selected" {
		return fmt.Errorf("账号模式无效")
	}
	if s.IntervalMinutes < 10 || s.IntervalMinutes > 525600 {
		return fmt.Errorf("间隔必须为 10–525600 分钟")
	}
	if s.Concurrency < 1 || s.Concurrency > 50 {
		return fmt.Errorf("并发数必须为 1–50")
	}
	if s.Enabled && (len(s.Targets) == 0 || s.AccountMode == "selected" && len(s.AccountIDs) == 0) {
		return fmt.Errorf("启用探测需要选择账号和至少一个模型")
	}
	seen := map[string]bool{}
	for i := range s.Targets {
		t := &s.Targets[i]
		t.Model = strings.TrimSpace(t.Model)
		t.Expected = strings.TrimSpace(t.Expected)
		if t.Protocol != "codex" && t.Protocol != "bps" {
			return fmt.Errorf("协议只能为 codex 或 bps")
		}
		if t.Model == "" || len(t.Model) > 256 || len(t.Expected) > 256 {
			return fmt.Errorf("模型名不能为空且不能超过 256 字节")
		}
		if seen[t.key()] {
			return fmt.Errorf("协议和模型组合不能重复")
		}
		seen[t.key()] = true
	}
	// 自动调度列表不要求账号仍可探测：已删除账号的残留 ID 在界面不可见，运行时读取账号后再判断。
	for _, list := range [][]int64{s.AccountIDs, s.AutoScheduleAccountIDs} {
		ids := map[int64]bool{}
		for _, id := range list {
			if id <= 0 || ids[id] {
				return fmt.Errorf("账号 ID 无效或重复")
			}
			ids[id] = true
		}
	}
	return nil
}
func ModelTraceEligible(a *Account) bool {
	return a != nil && a.IsOpenAIOAuth() && !a.IsShadow() && !a.IsOpenAIAgentIdentity() && !a.IsOpenAIPersonalAccessToken()
}
func (s ModelTraceSettings) Includes(a *Account) bool {
	if !ModelTraceEligible(a) {
		return false
	}
	return s.includesID(a.ID)
}
func (s ModelTraceSettings) includesID(accountID int64) bool {
	if s.AccountMode == "all" {
		return true
	}
	for _, id := range s.AccountIDs {
		if id == accountID {
			return true
		}
	}
	return false
}

// autoSchedulesID 判断账号的调度开关是否由探测结果接管：功能启用、纳入探测、勾选开关三者同时成立。
// 勾选列表与纳入范围独立保存，未纳入探测的账号也可以预先勾选。
func (s ModelTraceSettings) autoSchedulesID(accountID int64) bool {
	return s.Enabled && s.includesID(accountID) && slices.Contains(s.AutoScheduleAccountIDs, accountID)
}
func (s *SettingService) GetModelTraceSettings(ctx context.Context) (ModelTraceSettings, error) {
	cfg := DefaultModelTraceSettings()
	raw, err := s.settingRepo.GetValue(ctx, modelTraceSettingKey)
	if errors.Is(err, ErrSettingNotFound) || err == nil && strings.TrimSpace(raw) == "" {
		return cfg, nil
	}
	if err != nil {
		return cfg, err
	}
	if err = json.Unmarshal([]byte(raw), &cfg); err != nil {
		return cfg, err
	}
	return cfg, cfg.Validate()
}
func (s *SettingService) SaveModelTraceSettings(ctx context.Context, cfg ModelTraceSettings) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	return s.settingRepo.Set(ctx, modelTraceSettingKey, string(raw))
}

type ModelTraceSample struct {
	modeltrace.Diagnostic
	HTTPStatus int    `json:"http_status"`
	Error      string `json:"error,omitempty"`
}
type ModelTraceResult struct {
	MatchedSince   *time.Time             `json:"-"`
	StreakExpected string                 `json:"-"`
	AccountID      int64                  `json:"account_id"`
	Protocol       string                 `json:"protocol"`
	Model          string                 `json:"model"`
	UpstreamModel  string                 `json:"upstream_model,omitempty"`
	Status         string                 `json:"status"`
	Prediction     string                 `json:"prediction,omitempty"`
	Probability    float64                `json:"probability"`
	Candidates     []modeltrace.Candidate `json:"candidates,omitempty"`
	Samples        []ModelTraceSample     `json:"samples,omitempty"`
	Error          string                 `json:"error,omitempty"`
	BankVersion    string                 `json:"bank_version"`
	StartedAt      time.Time              `json:"started_at"`
	FinishedAt     time.Time              `json:"finished_at"`
}
type ModelTraceDetail struct {
	ModelTraceResult
	Expected     string     `json:"expected_model"`
	Verdict      string     `json:"verdict"`
	MatchedSince *time.Time `json:"matched_since"`
}
type ModelTraceSummary struct {
	Enabled      bool               `json:"enabled"`
	Running      bool               `json:"running"`
	AutoSchedule bool               `json:"auto_schedule"`
	Matched      int                `json:"matched"`
	Mismatched   int                `json:"mismatched"`
	Details      []ModelTraceDetail `json:"details"`
}

func modelTraceSummary(cfg ModelTraceSettings, results []ModelTraceResult, running bool) *ModelTraceSummary {
	summary := &ModelTraceSummary{Enabled: cfg.Enabled, Running: running, Details: []ModelTraceDetail{}}
	byKey := map[string]ModelTraceResult{}
	for _, r := range results {
		byKey[r.Protocol+"\x00"+r.Model] = r
	}
	for _, t := range cfg.Targets {
		r, ok := byKey[t.key()]
		if !ok {
			r = ModelTraceResult{Protocol: t.Protocol, Model: t.Model, Status: "pending"}
		}
		d := ModelTraceDetail{ModelTraceResult: r, Expected: t.ExpectedModel(), Verdict: "unknown"}
		d.Verdict = ModelTraceVerdict(r, d.Expected)
		if d.Verdict == "matched" {
			summary.Matched++
			if cfg.Enabled && cfg.includesID(r.AccountID) && r.StreakExpected == d.Expected {
				d.MatchedSince = r.MatchedSince
			}
		} else if d.Verdict == "mismatched" {
			summary.Mismatched++
		}
		summary.Details = append(summary.Details, d)
	}
	return summary
}

type ModelTraceState struct {
	Running   bool
	Requested bool
	NextRunAt time.Time
}
type ModelTraceQueueResult struct {
	Accepted    int `json:"accepted"`
	Running     int `json:"running"`
	Unavailable int `json:"unavailable"`
}
type ModelTraceLease interface {
	Check(context.Context) error
	Close()
}
type ModelTraceRepository interface {
	UpdateSettings(context.Context, ModelTraceSettings, []int64) error
	BeginProbe(context.Context, int64, ModelTraceTarget) (*ModelTraceProbeSnapshot, error)
	History(context.Context, ModelTraceHistoryQuery) (ModelTraceHistoryPage, error)
	PruneHistory(context.Context) error
	Acquire(context.Context) (ModelTraceLease, error)
	Recover(context.Context, time.Duration) error
	ClearQueue(context.Context) error
	States(context.Context, []int64) (map[int64]ModelTraceState, error)
	Enqueue(context.Context, []int64) (ModelTraceQueueResult, error)
	Reschedule(context.Context, []int64) error
	Claim(context.Context, int64, string) (bool, error)
	Save(context.Context, ModelTraceResult, string, ModelTraceProbeSnapshot) error
	Finish(context.Context, int64, string, time.Duration) error
	Latest(context.Context, []int64) (map[int64][]ModelTraceResult, error)
}

// modelTraceAccounts 是探测对账号的全部访问面：读取，以及自动调度写入的调度开关。
type modelTraceAccounts interface {
	GetByID(context.Context, int64) (*Account, error)
	ListAllWithFilters(context.Context, string, string, string, string, int64, string) ([]Account, error)
	SetSchedulable(context.Context, int64, bool) error
}
