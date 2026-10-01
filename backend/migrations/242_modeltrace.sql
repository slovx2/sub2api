-- 探测状态与账号业务状态分表，禁止通过探测修改 accounts。
CREATE TABLE IF NOT EXISTS modeltrace_accounts (
 account_id BIGINT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
 running BOOLEAN NOT NULL DEFAULT FALSE,
 requested BOOLEAN NOT NULL DEFAULT FALSE,
 owner TEXT NOT NULL DEFAULT '',
 next_run_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS modeltrace_results (
 account_id BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
 protocol TEXT NOT NULL CHECK (protocol IN ('codex','bps')),
 model TEXT NOT NULL,
 result JSONB NOT NULL,
 updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 PRIMARY KEY (account_id, protocol, model)
);
