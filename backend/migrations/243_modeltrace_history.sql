-- 历史与连续匹配状态独立保存，不改动账号业务数据。
CREATE TABLE modeltrace_history (
 id BIGSERIAL PRIMARY KEY,
 account_id BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
 protocol TEXT NOT NULL CHECK (protocol IN ('codex','bps')),
 model TEXT NOT NULL,
 expected_model TEXT NOT NULL,
 verdict TEXT NOT NULL CHECK (verdict IN ('matched','mismatched','unknown')),
 finished_at TIMESTAMPTZ NOT NULL,
 result JSONB NOT NULL
);
CREATE INDEX modeltrace_history_account_time ON modeltrace_history(account_id,finished_at DESC,id DESC);
CREATE INDEX modeltrace_history_expiry ON modeltrace_history(finished_at);
CREATE TABLE modeltrace_streaks (
 account_id BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
 protocol TEXT NOT NULL,
 model TEXT NOT NULL,
 expected_model TEXT NOT NULL,
 generation BIGINT NOT NULL DEFAULT 1,
 active BOOLEAN NOT NULL DEFAULT TRUE,
 matched_since TIMESTAMPTZ,
 PRIMARY KEY (account_id,protocol,model)
);
