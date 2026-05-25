package legacy_payment

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

type OrderRepository interface {
	Create(ctx context.Context, order *Order) error
	GetByID(ctx context.Context, id int64) (*Order, error)
	GetByOrderNo(ctx context.Context, orderNo string) (*Order, error)
	ListByUserID(ctx context.Context, userID int64, page, pageSize int) ([]*Order, int64, error)
	UpdateAfterCreate(ctx context.Context, id int64, tradeNo, payType, payInfo string) error
	UpdateNotifyInfo(ctx context.Context, id int64, tradeNo, apiTradeNo, payType, payload string) error
	MarkPaid(ctx context.Context, id int64, paidAt time.Time) (bool, error)
	StartCrediting(ctx context.Context, id int64) (bool, error)
	RevertCrediting(ctx context.Context, id int64) error
	MarkCredited(ctx context.Context, id int64, creditedAt time.Time) error
	MarkFailed(ctx context.Context, id int64, reason string) error
	UpdateLastError(ctx context.Context, id int64, reason string) error
}

type orderRepository struct {
	db *sql.DB
}

func NewOrderRepository(db *sql.DB) OrderRepository {
	return &orderRepository{db: db}
}

func (r *orderRepository) Create(ctx context.Context, order *Order) error {
	if order == nil {
		return errors.New("nil order")
	}
	row := r.db.QueryRowContext(ctx, `
		INSERT INTO legacy_payment_orders (
			order_no,
			user_id,
			amount_cny,
			amount_usd,
			status,
			channel
		)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, created_at, updated_at
	`, order.OrderNo, order.UserID, order.AmountCNY, order.AmountUSD, order.Status, order.Channel)

	if err := row.Scan(&order.ID, &order.CreatedAt, &order.UpdatedAt); err != nil {
		return err
	}
	return nil
}

func (r *orderRepository) GetByID(ctx context.Context, id int64) (*Order, error) {
	return r.getByField(ctx, "id", id)
}

func (r *orderRepository) GetByOrderNo(ctx context.Context, orderNo string) (*Order, error) {
	return r.getByField(ctx, "order_no", orderNo)
}

func (r *orderRepository) ListByUserID(ctx context.Context, userID int64, page, pageSize int) ([]*Order, int64, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}

	var total int64
	if err := r.db.QueryRowContext(ctx, `
		SELECT COUNT(1)
		FROM legacy_payment_orders
		WHERE user_id = $1
	`, userID).Scan(&total); err != nil {
		return nil, 0, err
	}

	offset := (page - 1) * pageSize
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, order_no, trade_no, api_trade_no, user_id, amount_cny, amount_usd,
		       status, channel, pay_type, pay_info, notify_payload, last_error,
		       created_at, paid_at, credited_at, updated_at
		FROM legacy_payment_orders
		WHERE user_id = $1
		ORDER BY created_at DESC, id DESC
		LIMIT $2 OFFSET $3
	`, userID, pageSize, offset)
	if err != nil {
		return nil, 0, err
	}
	defer func() {
		_ = rows.Close()
	}()

	orders := make([]*Order, 0, pageSize)
	for rows.Next() {
		order, err := scanOrder(rows)
		if err != nil {
			return nil, 0, err
		}
		orders = append(orders, order)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return orders, total, nil
}

func (r *orderRepository) UpdateAfterCreate(ctx context.Context, id int64, tradeNo, payType, payInfo string) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE legacy_payment_orders
		SET trade_no = $1,
			pay_type = $2,
			pay_info = $3,
			status = $4,
			updated_at = NOW()
		WHERE id = $5
	`, tradeNo, payType, payInfo, StatusPaying, id)
	return err
}

func (r *orderRepository) UpdateNotifyInfo(ctx context.Context, id int64, tradeNo, apiTradeNo, payType, payload string) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE legacy_payment_orders
		SET trade_no = COALESCE(NULLIF($1, ''), trade_no),
			api_trade_no = COALESCE(NULLIF($2, ''), api_trade_no),
			pay_type = COALESCE(NULLIF($3, ''), pay_type),
			notify_payload = $4,
			updated_at = NOW()
		WHERE id = $5
	`, tradeNo, apiTradeNo, payType, payload, id)
	return err
}

func (r *orderRepository) MarkPaid(ctx context.Context, id int64, paidAt time.Time) (bool, error) {
	result, err := r.db.ExecContext(ctx, `
		UPDATE legacy_payment_orders
		SET status = $1,
			paid_at = $2,
			updated_at = NOW()
		WHERE id = $3
		  AND status IN ($4, $5)
	`, StatusPaid, paidAt, id, StatusCreated, StatusPaying)
	if err != nil {
		return false, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return affected > 0, nil
}

func (r *orderRepository) StartCrediting(ctx context.Context, id int64) (bool, error) {
	result, err := r.db.ExecContext(ctx, `
		UPDATE legacy_payment_orders
		SET status = $1,
			updated_at = NOW()
		WHERE id = $2
		  AND status = $3
	`, StatusCrediting, id, StatusPaid)
	if err != nil {
		return false, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return affected > 0, nil
}

func (r *orderRepository) RevertCrediting(ctx context.Context, id int64) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE legacy_payment_orders
		SET status = $1,
			updated_at = NOW()
		WHERE id = $2
		  AND status = $3
	`, StatusPaid, id, StatusCrediting)
	return err
}

func (r *orderRepository) MarkCredited(ctx context.Context, id int64, creditedAt time.Time) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE legacy_payment_orders
		SET status = $1,
			credited_at = $2,
			updated_at = NOW()
		WHERE id = $3
		  AND status = $4
	`, StatusCredited, creditedAt, id, StatusCrediting)
	return err
}

func (r *orderRepository) MarkFailed(ctx context.Context, id int64, reason string) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE legacy_payment_orders
		SET status = $1,
			last_error = $2,
			updated_at = NOW()
		WHERE id = $3
	`, StatusFailed, reason, id)
	return err
}

func (r *orderRepository) UpdateLastError(ctx context.Context, id int64, reason string) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE legacy_payment_orders
		SET last_error = $1,
			updated_at = NOW()
		WHERE id = $2
	`, reason, id)
	return err
}

func (r *orderRepository) getByField(ctx context.Context, field string, value any) (*Order, error) {
	query := `
		SELECT id, order_no, trade_no, api_trade_no, user_id, amount_cny, amount_usd,
		       status, channel, pay_type, pay_info, notify_payload, last_error,
		       created_at, paid_at, credited_at, updated_at
		FROM legacy_payment_orders
		WHERE ` + field + ` = $1
		LIMIT 1
	`
	row := r.db.QueryRowContext(ctx, query, value)

	order, err := scanOrder(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrOrderNotFound
		}
		return nil, err
	}
	return order, nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanOrder(row rowScanner) (*Order, error) {
	var (
		order         Order
		tradeNo       sql.NullString
		apiTradeNo    sql.NullString
		payType       sql.NullString
		payInfo       sql.NullString
		notifyPayload sql.NullString
		lastError     sql.NullString
		paidAt        sql.NullTime
		creditedAt    sql.NullTime
	)
	if err := row.Scan(
		&order.ID,
		&order.OrderNo,
		&tradeNo,
		&apiTradeNo,
		&order.UserID,
		&order.AmountCNY,
		&order.AmountUSD,
		&order.Status,
		&order.Channel,
		&payType,
		&payInfo,
		&notifyPayload,
		&lastError,
		&order.CreatedAt,
		&paidAt,
		&creditedAt,
		&order.UpdatedAt,
	); err != nil {
		return nil, err
	}
	if tradeNo.Valid {
		order.TradeNo = tradeNo.String
	}
	if apiTradeNo.Valid {
		order.APITradeNo = apiTradeNo.String
	}
	if payType.Valid {
		order.PayType = payType.String
	}
	if payInfo.Valid {
		order.PayInfo = payInfo.String
	}
	if notifyPayload.Valid {
		order.NotifyPayload = notifyPayload.String
	}
	if lastError.Valid {
		order.LastError = lastError.String
	}
	if paidAt.Valid {
		order.PaidAt = &paidAt.Time
	}
	if creditedAt.Valid {
		order.CreditedAt = &creditedAt.Time
	}
	return &order, nil
}
