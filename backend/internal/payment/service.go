package payment

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	baseservice "github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/google/uuid"
)

const (
	defaultDevice = "pc"
	methodJump    = "jump"
)

var validDevices = map[string]struct{}{
	"pc":     {},
	"mobile": {},
	"qq":     {},
	"wechat": {},
	"alipay": {},
}

type Service struct {
	cfg          *Config
	repo         OrderRepository
	provider     Provider
	adminService balanceAdminService
}

type balanceAdminService interface {
	UpdateUserBalance(ctx context.Context, userID int64, balance float64, operation string, notes string) (*baseservice.User, error)
}

func NewService(cfg *Config, repo OrderRepository, provider Provider, adminService balanceAdminService) *Service {
	return &Service{
		cfg:          cfg,
		repo:         repo,
		provider:     provider,
		adminService: adminService,
	}
}

func (s *Service) CreateOrder(ctx context.Context, req CreateOrderRequest) (*CreateOrderResult, error) {
	if !s.isEnabled() {
		return nil, ErrPaymentDisabled
	}
	if err := s.validateAmount(req.Amount); err != nil {
		return nil, err
	}
	channel := strings.TrimSpace(req.Channel)
	if channel != ChannelAlipay && channel != ChannelWxpay {
		return nil, ErrInvalidChannel
	}
	device := strings.TrimSpace(req.Device)
	if device == "" {
		device = defaultDevice
	}
	if _, ok := validDevices[device]; !ok {
		return nil, ErrInvalidDevice
	}
	clientIP := strings.TrimSpace(req.ClientIP)
	if clientIP == "" {
		return nil, ErrNotifyRejected
	}

	order := &Order{
		OrderNo:   newOrderNo(),
		UserID:    req.UserID,
		AmountCNY: req.Amount,
		AmountUSD: req.Amount,
		Status:    StatusCreated,
		Channel:   channel,
	}
	if err := s.repo.Create(ctx, order); err != nil {
		return nil, err
	}

	notifyURL := s.buildPublicURL("/api/v1/payments/notify")
	returnURL := s.buildPublicURL("/api/v1/payments/return")

	providerResp, err := s.provider.CreatePayment(ctx, ProviderCreateRequest{
		OutTradeNo: order.OrderNo,
		Method:     methodJump,
		Channel:    channel,
		Amount:     formatAmount(req.Amount),
		NotifyURL:  notifyURL,
		ReturnURL:  returnURL,
		ClientIP:   clientIP,
		Device:     device,
		Subject:    "余额充值",
		Param:      order.OrderNo,
	})
	if err != nil {
		_ = s.repo.MarkFailed(ctx, order.ID, err.Error())
		return nil, err
	}

	order.TradeNo = providerResp.TradeNo
	order.PayType = providerResp.PayType
	order.PayInfo = providerResp.PayInfo
	order.Status = StatusPaying
	if err := s.repo.UpdateAfterCreate(ctx, order.ID, order.TradeNo, order.PayType, order.PayInfo); err != nil {
		return nil, err
	}

	return &CreateOrderResult{
		Order:   order,
		PayType: order.PayType,
		PayInfo: order.PayInfo,
	}, nil
}

func (s *Service) GetOrder(ctx context.Context, userID, orderID int64) (*OrderStatusResult, error) {
	order, err := s.repo.GetByID(ctx, orderID)
	if err != nil {
		return nil, err
	}
	if order.UserID != userID {
		return nil, ErrOrderForbidden
	}
	return &OrderStatusResult{
		ID:         order.ID,
		OrderNo:    order.OrderNo,
		Status:     order.Status,
		Amount:     order.AmountCNY,
		Channel:    order.Channel,
		PayType:    order.PayType,
		PayInfo:    order.PayInfo,
		CreatedAt:  order.CreatedAt,
		PaidAt:     order.PaidAt,
		CreditedAt: order.CreditedAt,
	}, nil
}

func (s *Service) ListOrders(ctx context.Context, userID int64, page, pageSize int) ([]*Order, int64, error) {
	if s == nil || s.repo == nil {
		return nil, 0, ErrPaymentDisabled
	}
	return s.repo.ListByUserID(ctx, userID, page, pageSize)
}

func (s *Service) PublicConfig() PublicConfig {
	if s == nil || s.cfg == nil {
		return DefaultConfig().PublicConfig()
	}
	return s.cfg.PublicConfig()
}

func (s *Service) HandleNotify(ctx context.Context, params map[string]string, rawQuery string) error {
	if !s.isEnabled() {
		return ErrPaymentDisabled
	}
	if err := s.provider.VerifySign(params, params["sign"]); err != nil {
		return err
	}
	if params["trade_status"] != "TRADE_SUCCESS" {
		return ErrNotifyRejected
	}
	if err := s.checkTimestamp(params["timestamp"]); err != nil {
		return err
	}
	if !s.matchMerchantID(params["pid"]) {
		return ErrNotifyRejected
	}

	orderNo := strings.TrimSpace(params["out_trade_no"])
	if orderNo == "" {
		return ErrNotifyRejected
	}
	order, err := s.repo.GetByOrderNo(ctx, orderNo)
	if err != nil {
		return err
	}
	if params["type"] != "" && params["type"] != order.Channel {
		return ErrNotifyRejected
	}
	amount, err := parseAmount(params["money"])
	if err != nil {
		return err
	}
	if amount != order.AmountCNY {
		return ErrNotifyRejected
	}

	_ = s.repo.UpdateNotifyInfo(ctx, order.ID, params["trade_no"], params["api_trade_no"], params["type"], rawQuery)

	if order.Status == StatusCredited || order.Status == StatusCrediting {
		return nil
	}
	_, _ = s.repo.MarkPaid(ctx, order.ID, time.Now())

	ok, err := s.repo.StartCrediting(ctx, order.ID)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}

	notes := fmt.Sprintf("支付订单号: %s", order.OrderNo)
	if _, err := s.adminService.UpdateUserBalance(ctx, order.UserID, float64(order.AmountUSD), "add", notes); err != nil {
		_ = s.repo.UpdateLastError(ctx, order.ID, err.Error())
		_ = s.repo.RevertCrediting(ctx, order.ID)
		return err
	}

	if err := s.repo.MarkCredited(ctx, order.ID, time.Now()); err != nil {
		_ = s.repo.UpdateLastError(ctx, order.ID, err.Error())
		return err
	}
	return nil
}

func (s *Service) ResolveReturn(ctx context.Context, params map[string]string) (int64, error) {
	orderNo := strings.TrimSpace(params["out_trade_no"])
	if orderNo == "" {
		return 0, ErrOrderNotFound
	}
	order, err := s.repo.GetByOrderNo(ctx, orderNo)
	if err != nil {
		return 0, err
	}
	return order.ID, nil
}

func (s *Service) isEnabled() bool {
	if s.cfg == nil {
		return false
	}
	return s.cfg.Enabled
}

func (s *Service) validateAmount(amount int64) error {
	if amount <= 0 {
		return ErrInvalidAmount
	}
	if amount < s.cfg.MinAmount || amount > s.cfg.MaxAmount {
		return ErrInvalidAmount
	}
	if s.cfg.Step > 0 && amount%s.cfg.Step != 0 {
		return ErrInvalidAmount
	}
	return nil
}

func (s *Service) buildPublicURL(path string) string {
	base := strings.TrimRight(s.cfg.PublicBaseURL, "/")
	return base + path
}

func (s *Service) matchMerchantID(pid string) bool {
	if pid == "" {
		return false
	}
	return pid == strconv.FormatInt(s.cfg.PluginsWorld.MerchantID, 10)
}

func (s *Service) checkTimestamp(raw string) error {
	if raw == "" {
		return ErrNotifyRejected
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return ErrNotifyRejected
	}
	if s.cfg.TimestampSkewSeconds <= 0 {
		return nil
	}
	gap := time.Since(time.Unix(value, 0))
	if gap < 0 {
		gap = -gap
	}
	if gap > time.Duration(s.cfg.TimestampSkewSeconds)*time.Second {
		return ErrNotifyRejected
	}
	return nil
}

func newOrderNo() string {
	return strings.ReplaceAll(uuid.NewString(), "-", "")
}

func formatAmount(amount int64) string {
	return fmt.Sprintf("%d.00", amount)
}

func parseAmount(raw string) (int64, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return 0, ErrNotifyRejected
	}
	if strings.Contains(value, ".") {
		parts := strings.SplitN(value, ".", 2)
		if len(parts) != 2 {
			return 0, ErrNotifyRejected
		}
		if parts[1] != "" && strings.TrimRight(parts[1], "0") != "" {
			return 0, ErrNotifyRejected
		}
		value = parts[0]
	}
	amount, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, ErrNotifyRejected
	}
	return amount, nil
}
