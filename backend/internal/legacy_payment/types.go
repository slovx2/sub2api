package legacy_payment

import "time"

const (
	StatusCreated   = "created"
	StatusPaying    = "paying"
	StatusPaid      = "paid"
	StatusCrediting = "crediting"
	StatusCredited  = "credited"
	StatusFailed    = "failed"
	StatusClosed    = "closed"
)

const (
	ChannelAlipay = "alipay"
	ChannelWxpay  = "wxpay"
)

type Order struct {
	ID            int64
	OrderNo       string
	TradeNo       string
	APITradeNo    string
	UserID        int64
	AmountCNY     int64
	AmountUSD     int64
	Status        string
	Channel       string
	PayType       string
	PayInfo       string
	NotifyPayload string
	LastError     string
	CreatedAt     time.Time
	PaidAt        *time.Time
	CreditedAt    *time.Time
	UpdatedAt     time.Time
}

type CreateOrderResult struct {
	Order   *Order
	PayType string
	PayInfo string
}

type CreateOrderRequest struct {
	UserID   int64
	Amount   int64
	Channel  string
	Device   string
	ClientIP string
}

type OrderStatusResult struct {
	ID         int64
	OrderNo    string
	Status     string
	Amount     int64
	Channel    string
	PayType    string
	PayInfo    string
	CreatedAt  time.Time
	PaidAt     *time.Time
	CreditedAt *time.Time
}

type PublicConfig struct {
	Enabled   bool  `json:"enabled"`
	MinAmount int64 `json:"min_amount"`
	MaxAmount int64 `json:"max_amount"`
	Step      int64 `json:"step"`
}
