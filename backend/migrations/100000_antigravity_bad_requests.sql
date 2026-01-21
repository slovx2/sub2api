-- +goose Up
CREATE TABLE IF NOT EXISTS antigravity_bad_requests (
    id BIGSERIAL PRIMARY KEY,
    account_id BIGINT NOT NULL,
    account_name VARCHAR(255),
    request_id VARCHAR(64),
    status_code INT NOT NULL DEFAULT 400,
    request_body TEXT,
    response_body TEXT,
    error_message VARCHAR(1024),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_antigravity_bad_requests_created_at ON antigravity_bad_requests(created_at DESC);

-- +goose Down
DROP TABLE IF EXISTS antigravity_bad_requests;
