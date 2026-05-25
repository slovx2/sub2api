-- 将本分支的 Plugins World 充值订单和上游 payment_orders 隔离。
-- 旧版本把自定义充值订单建在 payment_orders 表里，上游后来引入了同名表。
-- 在上游 092 迁移前先把旧表改名，避免两套支付逻辑抢同一个表结构。
DO $$
BEGIN
    IF to_regclass('public.payment_orders') IS NOT NULL
       AND to_regclass('public.legacy_payment_orders') IS NULL
       AND EXISTS (
           SELECT 1 FROM information_schema.columns
           WHERE table_schema = 'public'
             AND table_name = 'payment_orders'
             AND column_name = 'order_no'
       )
       AND EXISTS (
           SELECT 1 FROM information_schema.columns
           WHERE table_schema = 'public'
             AND table_name = 'payment_orders'
             AND column_name = 'amount_cny'
       )
       AND NOT EXISTS (
           SELECT 1 FROM information_schema.columns
           WHERE table_schema = 'public'
             AND table_name = 'payment_orders'
             AND column_name = 'expires_at'
       )
    THEN
        ALTER TABLE public.payment_orders RENAME TO legacy_payment_orders;

        IF EXISTS (
            SELECT 1 FROM pg_constraint
            WHERE conrelid = 'public.legacy_payment_orders'::regclass
              AND conname = 'payment_orders_pkey'
        ) THEN
            ALTER TABLE public.legacy_payment_orders
                RENAME CONSTRAINT payment_orders_pkey TO legacy_payment_orders_pkey;
        END IF;

        IF EXISTS (
            SELECT 1 FROM pg_constraint
            WHERE conrelid = 'public.legacy_payment_orders'::regclass
              AND conname = 'payment_orders_order_no_key'
        ) THEN
            ALTER TABLE public.legacy_payment_orders
                RENAME CONSTRAINT payment_orders_order_no_key TO legacy_payment_orders_order_no_key;
        END IF;

        ALTER INDEX IF EXISTS public.idx_payment_orders_user_id RENAME TO idx_legacy_payment_orders_user_id;
        ALTER INDEX IF EXISTS public.idx_payment_orders_status RENAME TO idx_legacy_payment_orders_status;
        ALTER INDEX IF EXISTS public.idx_payment_orders_trade_no RENAME TO idx_legacy_payment_orders_trade_no;

        IF to_regclass('public.payment_orders_id_seq') IS NOT NULL THEN
            ALTER SEQUENCE public.payment_orders_id_seq RENAME TO legacy_payment_orders_id_seq;
            ALTER TABLE public.legacy_payment_orders
                ALTER COLUMN id SET DEFAULT nextval('public.legacy_payment_orders_id_seq'::regclass);
            ALTER SEQUENCE public.legacy_payment_orders_id_seq OWNED BY public.legacy_payment_orders.id;
        END IF;
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS legacy_payment_orders (
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

CREATE INDEX IF NOT EXISTS idx_legacy_payment_orders_user_id ON legacy_payment_orders(user_id);
CREATE INDEX IF NOT EXISTS idx_legacy_payment_orders_status ON legacy_payment_orders(status);
CREATE INDEX IF NOT EXISTS idx_legacy_payment_orders_trade_no ON legacy_payment_orders(trade_no);
