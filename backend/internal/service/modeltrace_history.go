package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"strings"
	"time"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
)

// ActiveTarget 用实际预期值比较，显式填写请求模型与留空含义相同。
func (s ModelTraceSettings) ActiveTarget(id int64, protocol, model string) (ModelTraceTarget, bool) {
	if s.Enabled && s.includesID(id) {
		for _, t := range s.Targets {
			if t.Protocol == protocol && t.Model == model {
				return t, true
			}
		}
	}
	return ModelTraceTarget{}, false
}

// modelTraceMinProbability 是计入匹配或不匹配所需的置信度下限，最高概率必须严格大于它。
const modelTraceMinProbability = .6

func ModelTraceVerdict(r ModelTraceResult, expected string) string {
	if r.Status != "success" || r.Probability <= modelTraceMinProbability {
		return "unknown"
	}
	if r.Prediction == expected {
		return "matched"
	}
	return "mismatched"
}

// modelTraceAutoSchedule 沿用连续匹配的口径聚合一轮结果：完成评分但不符合预期即关闭调度，
// 当前目标全部匹配才打开；只有失败或缺少结果时返回 nil，保持现状。
func modelTraceAutoSchedule(targets []ModelTraceTarget, round []ModelTraceResult) *bool {
	byKey := map[string]ModelTraceResult{}
	for _, r := range round {
		byKey[r.Protocol+"\x00"+r.Model] = r
	}
	matched := 0
	for _, t := range targets {
		r, ok := byKey[t.key()]
		if !ok || r.Status != "success" {
			continue
		}
		if ModelTraceVerdict(r, t.ExpectedModel()) != "matched" {
			schedulable := false
			return &schedulable
		}
		matched++
	}
	if matched == 0 || matched != len(targets) {
		return nil
	}
	schedulable := true
	return &schedulable
}

// modelTraceCanOpen 排除被其它机制关闭、不应由探测重新打开的账号：BPS 403 停调需人工确认，
// error 状态必须保持不可调度，已过期账号会被过期任务再次暂停。
func modelTraceCanOpen(a *Account, now time.Time) bool {
	if a.Extra[ExcelBPS403DisabledAtKey] != nil || a.Status == StatusError {
		return false
	}
	return !a.AutoPauseOnExpired || a.ExpiresAt == nil || now.Before(*a.ExpiresAt)
}

// 错误（含样本不足）保留起点；只有完成评分才能建立或中断连续段。
func ModelTraceNextMatchedSince(previous *time.Time, r ModelTraceResult, expected string) *time.Time {
	if r.Status != "success" {
		return previous
	}
	if ModelTraceVerdict(r, expected) != "matched" {
		return nil
	}
	if previous != nil {
		return previous
	}
	t := r.FinishedAt
	return &t
}

type ModelTraceProbeSnapshot struct {
	Target     ModelTraceTarget
	Generation int64
}

type ModelTraceHistoryEntry struct {
	ModelTraceResult
	ID       int64  `json:"id"`
	Expected string `json:"expected_model"`
	Verdict  string `json:"verdict"`
}
type ModelTraceHistoryCursor struct {
	ID         int64     `json:"id"`
	FinishedAt time.Time `json:"finished_at"`
}
type ModelTraceHistoryQuery struct {
	AccountID int64
	Protocol  string
	Model     string
	Before    *ModelTraceHistoryCursor
}
type ModelTraceHistoryPage struct {
	Items      []ModelTraceHistoryEntry `json:"items"`
	NextCursor string                   `json:"next_cursor,omitempty"`
}

func ModelTraceEncodeCursor(entry ModelTraceHistoryEntry) string {
	raw, _ := json.Marshal(ModelTraceHistoryCursor{entry.ID, entry.FinishedAt})
	return base64.RawURLEncoding.EncodeToString(raw)
}

func (s *ModelTraceService) History(ctx context.Context, id int64, protocol, model, cursor string) (ModelTraceHistoryPage, error) {
	query := ModelTraceHistoryQuery{AccountID: id, Protocol: protocol, Model: strings.TrimSpace(model)}
	if id <= 0 || protocol != "" && protocol != "codex" && protocol != "bps" || len(model) > 256 {
		return ModelTraceHistoryPage{}, infraerrors.BadRequest("INVALID_MODELTRACE_HISTORY", "探测历史筛选无效")
	}
	if cursor != "" {
		if len(cursor) > 512 {
			return ModelTraceHistoryPage{}, infraerrors.BadRequest("INVALID_MODELTRACE_CURSOR", "探测历史游标无效")
		}
		var before ModelTraceHistoryCursor
		raw, err := base64.RawURLEncoding.DecodeString(cursor)
		if err != nil || json.Unmarshal(raw, &before) != nil || before.ID <= 0 || before.FinishedAt.IsZero() {
			return ModelTraceHistoryPage{}, infraerrors.BadRequest("INVALID_MODELTRACE_CURSOR", "探测历史游标无效")
		}
		query.Before = &before
	}
	return s.repo.History(ctx, query)
}

func (s *ModelTraceService) maintainHistory(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		cleanupCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := s.repo.PruneHistory(cleanupCtx)
		cancel()
		if err != nil && ctx.Err() == nil {
			slog.Warn("modeltrace_history_cleanup_failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
