package payment

import (
	"context"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestServiceHandleNotifySuccess(t *testing.T) {
	service, repo, admin, keys, cfg := newNotifyTestService(t)

	order := &Order{
		OrderNo:   "order_notify_1",
		UserID:    42,
		AmountCNY: 5,
		AmountUSD: 5,
		Status:    StatusPaying,
		Channel:   ChannelAlipay,
	}
	if err := repo.Create(context.Background(), order); err != nil {
		t.Fatalf("create order: %v", err)
	}

	params := buildNotifyParams(t, cfg, keys, order)
	rawQuery := encodeParams(params)

	if err := service.HandleNotify(context.Background(), params, rawQuery); err != nil {
		t.Fatalf("handle notify: %v", err)
	}

	updated, err := repo.GetByOrderNo(context.Background(), order.OrderNo)
	if err != nil {
		t.Fatalf("get order: %v", err)
	}
	if updated.Status != StatusCredited {
		t.Fatalf("status mismatch: %s", updated.Status)
	}
	if updated.PaidAt == nil || updated.CreditedAt == nil {
		t.Fatalf("expected paid and credited timestamps")
	}
	if admin.updateBalanceCalls != 1 {
		t.Fatalf("expected balance update once, got %d", admin.updateBalanceCalls)
	}
	if admin.lastUserID != order.UserID {
		t.Fatalf("user id mismatch: %d", admin.lastUserID)
	}
	if admin.lastAmount != float64(order.AmountUSD) {
		t.Fatalf("amount mismatch: %f", admin.lastAmount)
	}
	if admin.lastOperation != "add" {
		t.Fatalf("operation mismatch: %s", admin.lastOperation)
	}
	if !strings.Contains(admin.lastNotes, order.OrderNo) {
		t.Fatalf("notes missing order no: %s", admin.lastNotes)
	}
}

func TestServiceHandleNotifyRejectCases(t *testing.T) {
	cases := []struct {
		name      string
		setup     func(t *testing.T, cfg *Config, keys testKeys, order *Order) map[string]string
		expectErr error
	}{
		{
			name: "invalid_signature",
			setup: func(t *testing.T, cfg *Config, keys testKeys, order *Order) map[string]string {
				params := buildNotifyParams(t, cfg, keys, order)
				params["sign"] = "invalid"
				return params
			},
			expectErr: ErrSignatureInvalid,
		},
		{
			name: "trade_status_not_success",
			setup: func(t *testing.T, cfg *Config, keys testKeys, order *Order) map[string]string {
				params := buildNotifyParams(t, cfg, keys, order)
				params["trade_status"] = "TRADE_CLOSED"
				params["sign"] = signParams(t, keys.platformPrivate, params)
				return params
			},
			expectErr: ErrNotifyRejected,
		},
		{
			name: "timestamp_skew",
			setup: func(t *testing.T, cfg *Config, keys testKeys, order *Order) map[string]string {
				params := buildNotifyParams(t, cfg, keys, order)
				old := time.Now().Add(-time.Duration(cfg.TimestampSkewSeconds+1) * time.Second)
				params["timestamp"] = strconv.FormatInt(old.Unix(), 10)
				params["sign"] = signParams(t, keys.platformPrivate, params)
				return params
			},
			expectErr: ErrNotifyRejected,
		},
		{
			name: "merchant_id_mismatch",
			setup: func(t *testing.T, cfg *Config, keys testKeys, order *Order) map[string]string {
				params := buildNotifyParams(t, cfg, keys, order)
				params["pid"] = "9999"
				params["sign"] = signParams(t, keys.platformPrivate, params)
				return params
			},
			expectErr: ErrNotifyRejected,
		},
		{
			name: "amount_mismatch",
			setup: func(t *testing.T, cfg *Config, keys testKeys, order *Order) map[string]string {
				params := buildNotifyParams(t, cfg, keys, order)
				params["money"] = "6.00"
				params["sign"] = signParams(t, keys.platformPrivate, params)
				return params
			},
			expectErr: ErrNotifyRejected,
		},
		{
			name: "amount_invalid_decimal",
			setup: func(t *testing.T, cfg *Config, keys testKeys, order *Order) map[string]string {
				params := buildNotifyParams(t, cfg, keys, order)
				params["money"] = "5.10"
				params["sign"] = signParams(t, keys.platformPrivate, params)
				return params
			},
			expectErr: ErrNotifyRejected,
		},
		{
			name: "channel_mismatch",
			setup: func(t *testing.T, cfg *Config, keys testKeys, order *Order) map[string]string {
				params := buildNotifyParams(t, cfg, keys, order)
				params["type"] = ChannelWxpay
				params["sign"] = signParams(t, keys.platformPrivate, params)
				return params
			},
			expectErr: ErrNotifyRejected,
		},
		{
			name: "order_not_found",
			setup: func(t *testing.T, cfg *Config, keys testKeys, order *Order) map[string]string {
				params := buildNotifyParams(t, cfg, keys, order)
				params["out_trade_no"] = "missing_order"
				params["sign"] = signParams(t, keys.platformPrivate, params)
				return params
			},
			expectErr: ErrOrderNotFound,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			service, repo, admin, keys, cfg := newNotifyTestService(t)
			order := &Order{
				OrderNo:   "order_notify_2",
				UserID:    42,
				AmountCNY: 5,
				AmountUSD: 5,
				Status:    StatusPaying,
				Channel:   ChannelAlipay,
			}
			if err := repo.Create(context.Background(), order); err != nil {
				t.Fatalf("create order: %v", err)
			}
			params := testCase.setup(t, cfg, keys, order)
			rawQuery := encodeParams(params)

			err := service.HandleNotify(context.Background(), params, rawQuery)
			if err == nil || !errors.Is(err, testCase.expectErr) {
				t.Fatalf("expected %v, got %v", testCase.expectErr, err)
			}
			if admin.updateBalanceCalls != 0 {
				t.Fatalf("unexpected balance updates: %d", admin.updateBalanceCalls)
			}
		})
	}
}

func TestServiceHandleNotifyIdempotent(t *testing.T) {
	service, repo, admin, keys, cfg := newNotifyTestService(t)

	order := &Order{
		OrderNo:   "order_notify_3",
		UserID:    42,
		AmountCNY: 5,
		AmountUSD: 5,
		Status:    StatusCredited,
		Channel:   ChannelAlipay,
	}
	if err := repo.Create(context.Background(), order); err != nil {
		t.Fatalf("create order: %v", err)
	}

	params := buildNotifyParams(t, cfg, keys, order)
	rawQuery := encodeParams(params)

	if err := service.HandleNotify(context.Background(), params, rawQuery); err != nil {
		t.Fatalf("handle notify: %v", err)
	}
	if admin.updateBalanceCalls != 0 {
		t.Fatalf("unexpected balance updates: %d", admin.updateBalanceCalls)
	}
}

func TestServiceHandleNotifyBalanceError(t *testing.T) {
	service, repo, admin, keys, cfg := newNotifyTestService(t)
	admin.updateBalanceErr = errors.New("balance update failed")

	order := &Order{
		OrderNo:   "order_notify_4",
		UserID:    42,
		AmountCNY: 5,
		AmountUSD: 5,
		Status:    StatusPaying,
		Channel:   ChannelAlipay,
	}
	if err := repo.Create(context.Background(), order); err != nil {
		t.Fatalf("create order: %v", err)
	}

	params := buildNotifyParams(t, cfg, keys, order)
	rawQuery := encodeParams(params)

	err := service.HandleNotify(context.Background(), params, rawQuery)
	if err == nil {
		t.Fatalf("expected error")
	}

	updated, err := repo.GetByOrderNo(context.Background(), order.OrderNo)
	if err != nil {
		t.Fatalf("get order: %v", err)
	}
	if updated.Status != StatusPaid {
		t.Fatalf("expected paid status, got %s", updated.Status)
	}
	if updated.LastError == "" {
		t.Fatalf("expected last error")
	}
	if admin.updateBalanceCalls != 1 {
		t.Fatalf("expected one balance update call, got %d", admin.updateBalanceCalls)
	}
}

func buildNotifyParams(t *testing.T, cfg *Config, keys testKeys, order *Order) map[string]string {
	t.Helper()
	params := map[string]string{
		"pid":          strconv.FormatInt(cfg.PluginsWorld.MerchantID, 10),
		"trade_no":     "trade_notify_1",
		"out_trade_no": order.OrderNo,
		"api_trade_no": "api_trade_1",
		"type":         order.Channel,
		"trade_status": "TRADE_SUCCESS",
		"money":        formatAmount(order.AmountCNY),
		"timestamp":    strconv.FormatInt(time.Now().Unix(), 10),
		"sign_type":    "RSA",
	}
	params["sign"] = signParams(t, keys.platformPrivate, params)
	return params
}

func encodeParams(params map[string]string) string {
	values := url.Values{}
	for key, value := range params {
		values.Set(key, value)
	}
	return values.Encode()
}

func newNotifyTestService(t *testing.T) (*Service, *memoryOrderRepo, *adminServiceStub, testKeys, *Config) {
	t.Helper()
	keys := newTestKeys(t)
	cfg := &Config{
		Enabled:              true,
		PublicBaseURL:        "https://example.com",
		MinAmount:            5,
		MaxAmount:            5000,
		Step:                 1,
		TimestampSkewSeconds: 180,
		PluginsWorld: PluginsWorldConfig{
			APIBaseURL:         "https://pay.plugins-world.cn",
			MerchantID:         1001,
			MerchantPrivateKey: keys.merchantPrivateBase64,
			PlatformPublicKey:  keys.platformPublicBase64,
		},
	}
	provider, err := NewPluginsWorldProvider(cfg)
	if err != nil {
		t.Fatalf("new provider: %v", err)
	}

	repo := newMemoryOrderRepo()
	admin := &adminServiceStub{}
	service := NewService(cfg, repo, provider, admin)
	return service, repo, admin, keys, cfg
}
