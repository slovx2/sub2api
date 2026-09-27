package repository

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	dbent "github.com/Wei-Shaw/sub2api/ent"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

var _ service.AccountExcelBPSUnscheduleRepository = (*accountRepository)(nil)

// UnscheduleExcelBPSOn403 在 BPS 返回 403 时一次性完成：关闭 BPS 协议、记录 403 时间、
// 把账号设为不可调度。凭据或开关期间被改动则放弃，避免误停人工恢复过的账号。
func (r *accountRepository) UnscheduleExcelBPSOn403(ctx context.Context, account *service.Account) (bool, error) {
	if !account.IsExcelBPSUnscheduleOn403Enabled() {
		return false, nil
	}
	if dbent.TxFromContext(ctx) != nil {
		return r.unscheduleExcelBPSOn403InTx(ctx, account)
	}
	tx, err := r.client.Tx(ctx)
	if errors.Is(err, dbent.ErrTxStarted) {
		return r.unscheduleExcelBPSOn403InTx(ctx, account)
	}
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	changed, err := r.unscheduleExcelBPSOn403InTx(dbent.NewTxContext(ctx, tx), account)
	if err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	if changed {
		r.syncSchedulerAccountSnapshot(ctx, account.ID)
	}
	return changed, nil
}

func (r *accountRepository) unscheduleExcelBPSOn403InTx(ctx context.Context, account *service.Account) (bool, error) {
	credentials, err := json.Marshal(account.Credentials)
	if err != nil {
		return false, err
	}
	disabledAt := time.Now().UTC().Format(time.RFC3339)
	client := clientFromContext(ctx, r.client)
	result, err := client.ExecContext(ctx, `
UPDATE accounts
SET extra = jsonb_set(
        jsonb_set(COALESCE(extra, '{}'::jsonb), '{openai_excel_bps}', 'false'::jsonb),
        '{openai_excel_bps_403_disabled_at}', to_jsonb($3::text)),
    schedulable = FALSE,
    updated_at = NOW()
WHERE id = $1 AND deleted_at IS NULL AND parent_account_id IS NULL
  AND platform = 'openai' AND type = 'oauth'
  AND credentials = $2::jsonb
  AND schedulable = TRUE
  AND extra -> 'openai_excel_bps' = 'true'::jsonb
  AND extra -> 'openai_excel_bps_unschedule_on_403' = 'true'::jsonb`,
		account.ID, string(credentials), disabledAt)
	if err != nil {
		return false, err
	}
	affected, err := result.RowsAffected()
	if err != nil || affected == 0 {
		return false, err
	}
	if err := enqueueSchedulerOutbox(ctx, client, service.SchedulerOutboxEventAccountChanged, &account.ID, nil, nil); err != nil {
		return false, err
	}
	return true, nil
}
