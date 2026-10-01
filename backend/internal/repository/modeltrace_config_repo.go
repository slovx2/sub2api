package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

// 配置、组合快照和结果写入共用短事务锁，与长驻调度锁分离。
const modelTraceConfigLockID int64 = 783284210722
const modelTraceCleanupLockID int64 = 783284210723

func (r *modelTraceRepository) configTransaction(ctx context.Context) (*sql.Tx, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock($1)", modelTraceConfigLockID); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	return tx, nil
}

func modelTraceConfig(ctx context.Context, tx *sql.Tx) (service.ModelTraceSettings, error) {
	cfg := service.DefaultModelTraceSettings()
	var raw string
	err := tx.QueryRowContext(ctx, "SELECT value FROM settings WHERE key='modeltrace'").Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
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

func (r *modelTraceRepository) UpdateSettings(ctx context.Context, cfg service.ModelTraceSettings, eligibleIDs []int64) error {
	tx, err := r.configTransaction(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	previous, err := modelTraceConfig(ctx, tx)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO settings(key,value,updated_at) VALUES('modeltrace',$1,NOW())
 ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value,updated_at=NOW()`, string(raw)); err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, "SELECT account_id,protocol,model,expected_model,active FROM modeltrace_streaks")
	if err != nil {
		return err
	}
	type reset struct {
		id                        int64
		protocol, model, expected string
		active                    bool
	}
	var changes []reset
	for rows.Next() {
		var old reset
		if err = rows.Scan(&old.id, &old.protocol, &old.model, &old.expected, &old.active); err != nil {
			rows.Close()
			return err
		}
		target, active := cfg.ActiveTarget(old.id, old.protocol, old.model)
		expected := old.expected
		if active {
			expected = target.ExpectedModel()
		}
		if active != old.active || expected != old.expected {
			changes = append(changes, reset{old.id, old.protocol, old.model, expected, active})
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, change := range changes {
		if _, err = tx.ExecContext(ctx, `UPDATE modeltrace_streaks SET active=$4,expected_model=$5,generation=generation+1,matched_since=NULL
 WHERE account_id=$1 AND protocol=$2 AND model=$3`, change.id, change.protocol, change.model, change.active, change.expected); err != nil {
			return err
		}
	}
	if !cfg.Enabled {
		if _, err = tx.ExecContext(ctx, "UPDATE modeltrace_accounts SET requested=FALSE,updated_at=NOW() WHERE requested"); err != nil {
			return err
		}
	} else {
		for _, id := range eligibleIDs {
			firstRound := false
			for _, target := range cfg.Targets {
				_, included := cfg.ActiveTarget(id, target.Protocol, target.Model)
				_, existed := previous.ActiveTarget(id, target.Protocol, target.Model)
				if included && !existed {
					firstRound = true
					break
				}
			}
			// 删除目标也需要尽快完成按新配置的一轮；仅修改预期不触发。
			if !firstRound && len(cfg.Targets) < len(previous.Targets) {
				for _, target := range cfg.Targets {
					if _, active := cfg.ActiveTarget(id, target.Protocol, target.Model); active {
						firstRound = true
						break
					}
				}
			}
			if firstRound {
				if _, err = tx.ExecContext(ctx, `INSERT INTO modeltrace_accounts(account_id,requested) VALUES($1,TRUE)
 ON CONFLICT(account_id) DO UPDATE SET requested=TRUE,updated_at=NOW()`, id); err != nil {
					return err
				}
			}
		}
	}
	return tx.Commit()
}

func (r *modelTraceRepository) BeginProbe(ctx context.Context, id int64, target service.ModelTraceTarget) (*service.ModelTraceProbeSnapshot, error) {
	tx, err := r.configTransaction(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	cfg, err := modelTraceConfig(ctx, tx)
	if err != nil {
		return nil, err
	}
	current, active := cfg.ActiveTarget(id, target.Protocol, target.Model)
	if !active {
		return nil, nil
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO modeltrace_streaks(account_id,protocol,model,expected_model)
 VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, id, current.Protocol, current.Model, current.ExpectedModel()); err != nil {
		return nil, err
	}
	snapshot := &service.ModelTraceProbeSnapshot{Target: current}
	if err = tx.QueryRowContext(ctx, `SELECT generation FROM modeltrace_streaks WHERE account_id=$1 AND protocol=$2 AND model=$3 AND active`,
		id, current.Protocol, current.Model).Scan(&snapshot.Generation); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return snapshot, nil
}
