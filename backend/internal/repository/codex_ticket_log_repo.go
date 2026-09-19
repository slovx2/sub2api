package repository

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

type codexTicketLogRepo struct{ db *sql.DB }

func NewCodexTicketLogRepository(db *sql.DB) service.CodexTicketLogRepository {
	return &codexTicketLogRepo{db: db}
}

func (r *codexTicketLogRepo) Create(ctx context.Context, e *service.CodexTicketEvent) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO codex_ticket_logs
		(account_id, account_name, model, kind, length, http_status, success, reason, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, e.AccountID, e.AccountName, e.Model, e.Kind, e.Length, e.HTTPStatus, e.Success, e.Reason, e.CreatedAt)
	return err
}

func (r *codexTicketLogRepo) List(ctx context.Context, filter service.CodexTicketLogFilter) (*service.CodexTicketLogPage, error) {
	if filter.Page < 1 {
		filter.Page = 1
	}
	if filter.PageSize < 1 || filter.PageSize > 100 {
		filter.PageSize = 20
	}
	// 同一快照内计算计数及分页，避免并发写入导致总数和当前页不一致。
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	where := " WHERE TRUE"
	args := []any{}
	if filter.AccountID > 0 {
		args = append(args, filter.AccountID)
		where += fmt.Sprintf(" AND account_id = $%d", len(args))
	}
	out := &service.CodexTicketLogPage{Items: []service.CodexTicketEvent{}}
	// 汇总按账号过滤，不随结果筛选变化；采票次数不包括注入缺失。
	err = tx.QueryRowContext(ctx, `SELECT count(*) FILTER (WHERE kind='harvest'),
		count(*) FILTER (WHERE kind='harvest' AND success),
		count(*) FILTER (WHERE kind='harvest' AND NOT success),
		count(*) FILTER (WHERE kind='injection_missing') FROM codex_ticket_logs`+where, args...).Scan(
		&out.Summary.Attempts, &out.Summary.Success, &out.Summary.Failure, &out.Summary.InjectionMissing)
	if err != nil {
		return nil, err
	}
	switch filter.Result {
	case "success":
		where += " AND kind='harvest' AND success"
	case "failure":
		where += " AND kind='harvest' AND NOT success"
	case "injection_missing":
		where += " AND kind='injection_missing'"
	}
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM codex_ticket_logs"+where, args...).Scan(&out.Total); err != nil {
		return nil, err
	}
	args = append(args, filter.PageSize, (filter.Page-1)*filter.PageSize)
	query := `SELECT id, account_id, account_name, model, kind, length, http_status, success, reason, created_at
		FROM codex_ticket_logs` + where + fmt.Sprintf(" ORDER BY id DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args))
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var e service.CodexTicketEvent
		if err = rows.Scan(&e.ID, &e.AccountID, &e.AccountName, &e.Model, &e.Kind, &e.Length, &e.HTTPStatus, &e.Success, &e.Reason, &e.CreatedAt); err != nil {
			return nil, err
		}
		out.Items = append(out.Items, e)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if err = rows.Close(); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return out, nil
}
