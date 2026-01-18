-- 支付订单表
CREATE TABLE IF NOT EXISTS payment_orders (
    id              BIGSERIAL PRIMARY KEY,
    order_no        VARCHAR(64) NOT NULL UNIQUE,
    user_id         BIGINT NOT NULL,
    trade_no        VARCHAR(64),
    api_trade_no    VARCHAR(64),
    amount_cny      BIGINT NOT NULL,
    amount_usd      BIGINT NOT NULL,
    status          VARCHAR(20) NOT NULL DEFAULT 'created',
    channel         VARCHAR(20) NOT NULL,
    pay_type        VARCHAR(20),
    pay_info        TEXT,
    notify_payload  TEXT,
    last_error      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    paid_at         TIMESTAMPTZ,
    credited_at     TIMESTAMPTZ,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_payment_orders_user_id ON payment_orders(user_id);
CREATE INDEX IF NOT EXISTS idx_payment_orders_status ON payment_orders(status);
CREATE INDEX IF NOT EXISTS idx_payment_orders_trade_no ON payment_orders(trade_no);
