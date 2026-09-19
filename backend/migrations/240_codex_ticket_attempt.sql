-- 每条实际采票日志记录共享轮次内的尝试序号；历史记录为 0。
ALTER TABLE codex_ticket_logs ADD COLUMN attempt INTEGER NOT NULL DEFAULT 0;
ALTER TABLE codex_ticket_logs DROP CONSTRAINT codex_ticket_logs_kind_check;
ALTER TABLE codex_ticket_logs ADD CONSTRAINT codex_ticket_logs_kind_check
    CHECK (kind IN ('harvest', 'injection_missing', 'cooldown'));
