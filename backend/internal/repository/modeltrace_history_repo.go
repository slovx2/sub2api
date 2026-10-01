package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

func (r *modelTraceRepository) History(ctx context.Context, query service.ModelTraceHistoryQuery) (service.ModelTraceHistoryPage, error) {
	page := service.ModelTraceHistoryPage{Items: []service.ModelTraceHistoryEntry{}}
	args := []any{query.AccountID}
	where := "account_id=$1 AND finished_at>=NOW()-INTERVAL '24 hours'"
	if query.Protocol != "" {
		args = append(args, query.Protocol)
		where += fmt.Sprintf(" AND protocol=$%d", len(args))
	}
	if query.Model != "" {
		args = append(args, query.Model)
		where += fmt.Sprintf(" AND model=$%d", len(args))
	}
	if query.Before != nil {
		args = append(args, query.Before.FinishedAt, query.Before.ID)
		where += fmt.Sprintf(" AND (finished_at,id)<($%d,$%d)", len(args)-1, len(args))
	}
	rows, err := r.db.QueryContext(ctx, "SELECT id,expected_model,verdict,finished_at,result FROM modeltrace_history WHERE "+where+" ORDER BY finished_at DESC,id DESC LIMIT 51", args...)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		var entry service.ModelTraceHistoryEntry
		var raw []byte
		var finished time.Time
		if err = rows.Scan(&entry.ID, &entry.Expected, &entry.Verdict, &finished, &raw); err != nil {
			return page, err
		}
		if err = json.Unmarshal(raw, &entry.ModelTraceResult); err != nil {
			return page, err
		}
		// 游标使用数据库时间精度，避免纳秒到微秒转换产生重复或遗漏。
		entry.FinishedAt = finished
		page.Items = append(page.Items, entry)
	}
	if err = rows.Err(); err != nil {
		return page, err
	}
	if len(page.Items) > 50 {
		page.Items = page.Items[:50]
		page.NextCursor = service.ModelTraceEncodeCursor(page.Items[49])
	}
	return page, nil
}

func (r *modelTraceRepository) PruneHistory(ctx context.Context) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var locked bool
	if err = tx.QueryRowContext(ctx, "SELECT pg_try_advisory_xact_lock($1)", modelTraceCleanupLockID).Scan(&locked); err != nil {
		return err
	}
	if !locked {
		return nil
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM modeltrace_history WHERE finished_at<NOW()-INTERVAL '24 hours'"); err != nil {
		return err
	}
	return tx.Commit()
}
