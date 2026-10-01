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

func ModelTraceVerdict(r ModelTraceResult, expected string) string {
	if r.Status != "success" || r.Probability <= .9 {
		return "unknown"
	}
	if r.Prediction == expected {
		return "matched"
	}
	return "mismatched"
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
