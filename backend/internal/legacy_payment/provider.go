package legacy_payment

import "context"

type Provider interface {
	CreatePayment(ctx context.Context, req ProviderCreateRequest) (*ProviderCreateResponse, error)
	VerifySign(params map[string]string, sign string) error
}

type ProviderCreateRequest struct {
	OutTradeNo string
	Method     string
	Channel    string
	Amount     string
	NotifyURL  string
	ReturnURL  string
	ClientIP   string
	Device     string
	Subject    string
	Param      string
}

type ProviderCreateResponse struct {
	TradeNo string
	PayType string
	PayInfo string
}
