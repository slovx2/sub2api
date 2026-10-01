package repository

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

type modelTraceRepository struct{ db *sql.DB }

func NewModelTraceRepository(db *sql.DB) service.ModelTraceRepository {
	return &modelTraceRepository{db}
}

type modelTraceLease struct{ conn *sql.Conn }

const modelTraceLockID int64 = 783284210721

func (r *modelTraceRepository) Acquire(ctx context.Context) (service.ModelTraceLease, error) {
	conn, err := r.db.Conn(ctx)
	if err != nil {
		return nil, err
	}
	var locked bool
	if err = conn.QueryRowContext(ctx, "SELECT pg_try_advisory_lock($1)", modelTraceLockID).Scan(&locked); err != nil || !locked {
		if err != nil {
			_ = conn.Raw(func(any) error { return driver.ErrBadConn })
		}
		conn.Close()
		return nil, err
	}
	return &modelTraceLease{conn}, nil
}
func (l *modelTraceLease) Check(ctx context.Context) error {
	var n int
	return l.conn.QueryRowContext(ctx, "SELECT 1").Scan(&n)
}
func (l *modelTraceLease) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := l.conn.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", modelTraceLockID); err != nil {
		// 不能将可能仍持有 session lock 的连接放回连接池。
		_ = l.conn.Raw(func(any) error { return driver.ErrBadConn })
	}
	_ = l.conn.Close()
}
func (r *modelTraceRepository) Recover(ctx context.Context, delay time.Duration) error {
	_, err := r.db.ExecContext(ctx, `UPDATE modeltrace_accounts SET running=FALSE,owner='',requested=FALSE,next_run_at=NOW()+$1*INTERVAL '1 second',updated_at=NOW() WHERE running`, delay.Seconds())
	return err
}
func modelTraceIDClause(ids []int64) (string, []any) {
	keys := make([]string, len(ids))
	args := make([]any, len(ids))
	for i, id := range ids {
		keys[i] = fmt.Sprintf("$%d", i+1)
		args[i] = id
	}
	return strings.Join(keys, ","), args
}
func (r *modelTraceRepository) States(ctx context.Context, ids []int64) (map[int64]service.ModelTraceState, error) {
	result := map[int64]service.ModelTraceState{}
	if len(ids) == 0 {
		return result, nil
	}
	clause, args := modelTraceIDClause(ids)
	rows, err := r.db.QueryContext(ctx, "SELECT account_id,running,requested,next_run_at FROM modeltrace_accounts WHERE account_id IN ("+clause+")", args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var s service.ModelTraceState
		if err = rows.Scan(&id, &s.Running, &s.Requested, &s.NextRunAt); err != nil {
			return nil, err
		}
		result[id] = s
	}
	return result, rows.Err()
}
func (r *modelTraceRepository) Enqueue(ctx context.Context, ids []int64) (service.ModelTraceQueueResult, error) {
	out := service.ModelTraceQueueResult{}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	for _, id := range ids {
		result, e := tx.ExecContext(ctx, `INSERT INTO modeltrace_accounts(account_id,requested) VALUES($1,TRUE)
   ON CONFLICT(account_id) DO UPDATE SET requested=TRUE,updated_at=NOW() WHERE NOT modeltrace_accounts.running AND NOT modeltrace_accounts.requested`, id)
		if e != nil {
			return out, e
		}
		n, e := result.RowsAffected()
		if e != nil {
			return out, e
		}
		if n > 0 {
			out.Accepted++
		} else {
			out.Running++
		}
	}
	return out, tx.Commit()
}
func (r *modelTraceRepository) Claim(ctx context.Context, id int64, owner string) (bool, error) {
	result, err := r.db.ExecContext(ctx, `INSERT INTO modeltrace_accounts(account_id,running,owner) VALUES($1,TRUE,$2)
 ON CONFLICT(account_id) DO UPDATE SET running=TRUE,requested=FALSE,owner=$2,updated_at=NOW()
 WHERE NOT modeltrace_accounts.running AND (modeltrace_accounts.requested OR modeltrace_accounts.next_run_at<=NOW())`, id, owner)
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	return n > 0, err
}
func (r *modelTraceRepository) Save(ctx context.Context, result service.ModelTraceResult, owner string, snapshot service.ModelTraceProbeSnapshot) error {
	if result.Protocol != snapshot.Target.Protocol || result.Model != snapshot.Target.Model {
		return fmt.Errorf("探测结果与请求快照不一致")
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return err
	}
	tx, err := r.configTransaction(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var valid bool
	err = tx.QueryRowContext(ctx, "SELECT running AND owner=$2 FROM modeltrace_accounts WHERE account_id=$1 FOR UPDATE", result.AccountID, owner).Scan(&valid)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	if !valid {
		return nil
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO modeltrace_results(account_id,protocol,model,result) VALUES($1,$2,$3,$4::jsonb)
 ON CONFLICT(account_id,protocol,model) DO UPDATE SET result=EXCLUDED.result,updated_at=NOW()`, result.AccountID, result.Protocol, result.Model, string(raw)); err != nil {
		return err
	}
	expected := snapshot.Target.ExpectedModel()
	if _, err = tx.ExecContext(ctx, `INSERT INTO modeltrace_history(account_id,protocol,model,expected_model,verdict,finished_at,result)
 VALUES($1,$2,$3,$4,$5,$6,$7::jsonb)`, result.AccountID, result.Protocol, result.Model, expected, service.ModelTraceVerdict(result, expected), result.FinishedAt, string(raw)); err != nil {
		return err
	}
	var since *time.Time
	err = tx.QueryRowContext(ctx, `SELECT matched_since FROM modeltrace_streaks
 WHERE account_id=$1 AND protocol=$2 AND model=$3 AND active AND generation=$4 AND expected_model=$5`,
		result.AccountID, result.Protocol, result.Model, snapshot.Generation, expected).Scan(&since)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	// 旧代次的结果保留当次预期的历史，但不能重建已被配置变更清除的连续段。
	if err == nil {
		since = service.ModelTraceNextMatchedSince(since, result, expected)
		if _, err = tx.ExecContext(ctx, `UPDATE modeltrace_streaks SET matched_since=$4 WHERE account_id=$1 AND protocol=$2 AND model=$3`,
			result.AccountID, result.Protocol, result.Model, since); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func (r *modelTraceRepository) Finish(ctx context.Context, id int64, owner string, delay time.Duration) error {
	// 配置变化可在运行中提交新一轮；完成旧任务不能清除此标记。
	_, err := r.db.ExecContext(ctx, `UPDATE modeltrace_accounts SET running=FALSE,owner='',next_run_at=NOW()+$3*INTERVAL '1 second',updated_at=NOW() WHERE account_id=$1 AND owner=$2`, id, owner, delay.Seconds())
	return err
}

func (r *modelTraceRepository) Reschedule(ctx context.Context, ids []int64) error {
	if len(ids) == 0 {
		return nil
	}
	clause, args := modelTraceIDClause(ids)
	_, err := r.db.ExecContext(ctx, `INSERT INTO modeltrace_accounts(account_id,requested)
 SELECT id,TRUE FROM accounts WHERE id IN (`+clause+`)
 ON CONFLICT(account_id) DO UPDATE SET requested=TRUE,updated_at=NOW()`, args...)
	return err
}
func (r *modelTraceRepository) Latest(ctx context.Context, ids []int64) (map[int64][]service.ModelTraceResult, error) {
	out := map[int64][]service.ModelTraceResult{}
	if len(ids) == 0 {
		return out, nil
	}
	clause, args := modelTraceIDClause(ids)
	rows, err := r.db.QueryContext(ctx, `SELECT r.account_id,r.result,s.matched_since,COALESCE(s.expected_model,'')
 FROM modeltrace_results r LEFT JOIN modeltrace_streaks s ON s.account_id=r.account_id AND s.protocol=r.protocol AND s.model=r.model AND s.active
 WHERE r.account_id IN (`+clause+")", args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var raw []byte
		var result service.ModelTraceResult
		var since *time.Time
		var expected string
		if err = rows.Scan(&id, &raw, &since, &expected); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(raw, &result); err != nil {
			return nil, err
		}
		result.MatchedSince, result.StreakExpected = since, expected
		out[id] = append(out[id], result)
	}
	return out, rows.Err()
}

func (r *modelTraceRepository) ClearQueue(ctx context.Context) error {
	_, err := r.db.ExecContext(ctx, "UPDATE modeltrace_accounts SET requested=FALSE,updated_at=NOW() WHERE requested")
	return err
}
