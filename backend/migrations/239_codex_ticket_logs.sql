-- 仅保存打票诊断元数据；不关联账号外键，以便账号删除后保留历史。
CREATE TABLE IF NOT EXISTS codex_ticket_logs (
    id BIGSERIAL PRIMARY KEY,
    account_id BIGINT NOT NULL,
    account_name TEXT NOT NULL,
    model TEXT NOT NULL,
    kind VARCHAR(32) NOT NULL CHECK (kind IN ('harvest', 'injection_missing')),
    length INTEGER NOT NULL DEFAULT 0,
    http_status INTEGER NOT NULL DEFAULT 0,
    success BOOLEAN NOT NULL DEFAULT FALSE,
    reason VARCHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_codex_ticket_logs_account_id_id ON codex_ticket_logs (account_id, id DESC);
