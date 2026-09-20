-- 一次性替换请求式策略，不在运行代码保留旧字段兼容。
UPDATE settings SET value = jsonb_build_object(
    'ttl_seconds', (value::jsonb)->'ttl_seconds',
    'refresh_before_seconds', (value::jsonb)->'refresh_before_seconds',
    'harvest_interval_seconds', 20,
    'max_consecutive_failures', 30
)::text, updated_at = NOW()
WHERE key = 'openai_codex_ticket_policy'
  AND (value::jsonb ? 'max_attempts' OR value::jsonb ? 'failure_cooldown_seconds');

ALTER TABLE codex_ticket_logs DROP CONSTRAINT codex_ticket_logs_kind_check;
ALTER TABLE codex_ticket_logs ADD CONSTRAINT codex_ticket_logs_kind_check
    CHECK (kind IN ('harvest', 'injection_missing', 'cooldown', 'account_error', 'account_error_write_failed'));

-- 精确识别旧采票冷却，不清理限流、过载、其他规则或人工设置。
WITH cleared AS (
    UPDATE accounts SET temp_unschedulable_until = NULL, temp_unschedulable_reason = NULL, updated_at = NOW()
    WHERE platform = 'openai' AND temp_unschedulable_reason = 'codex ticket attempts exhausted'
    RETURNING id
)
INSERT INTO scheduler_outbox(event_type, account_id)
SELECT 'account_changed', id FROM cleared;
