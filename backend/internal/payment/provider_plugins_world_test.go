package payment

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

func TestPluginsWorldProviderCreatePaymentSuccess(t *testing.T) {
	keys := newTestKeys(t)
	merchantID := int64(1001)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected method: %s", r.Method)
		}
		if r.URL.Path != "/api/pay/create" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		params := valuesToMap(r.PostForm)

		if params["pid"] != strconv.FormatInt(merchantID, 10) {
			t.Fatalf("pid mismatch: %s", params["pid"])
		}
		if params["method"] != methodJump {
			t.Fatalf("method mismatch: %s", params["method"])
		}
		if params["type"] != ChannelAlipay {
			t.Fatalf("type mismatch: %s", params["type"])
		}
		if params["money"] != "5.00" {
			t.Fatalf("money mismatch: %s", params["money"])
		}
		if params["clientip"] != "127.0.0.1" {
			t.Fatalf("clientip mismatch: %s", params["clientip"])
		}
		if params["sign_type"] != "RSA" {
			t.Fatalf("sign_type mismatch: %s", params["sign_type"])
		}
		if params["timestamp"] == "" {
			t.Fatalf("timestamp missing")
		}
		if err := verifySignature(keys.merchantPublic, params, params["sign"]); err != nil {
			t.Fatalf("request sign invalid: %v", err)
		}

		respParams := map[string]string{
			"code":      "0",
			"msg":       "ok",
			"trade_no":  "trade_10001",
			"pay_type":  "jump",
			"pay_info":  "https://pay.example.com/jump",
			"timestamp": strconv.FormatInt(1710000000, 10),
			"sign_type": "RSA",
		}
		respParams["sign"] = signParams(t, keys.platformPrivate, respParams)

		payload := pluginsWorldCreateResponse{
			Code:      0,
			Msg:       "ok",
			TradeNo:   respParams["trade_no"],
			PayType:   respParams["pay_type"],
			PayInfo:   respParams["pay_info"],
			Timestamp: respParams["timestamp"],
			Sign:      respParams["sign"],
			SignType:  respParams["sign_type"],
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(payload); err != nil {
			t.Fatalf("encode response: %v", err)
		}
	}))
	t.Cleanup(server.Close)

	cfg := &Config{
		Enabled:       true,
		PublicBaseURL: "https://example.com",
		MinAmount:     5,
		MaxAmount:     5000,
		Step:          1,
		PluginsWorld: PluginsWorldConfig{
			APIBaseURL:         server.URL,
			MerchantID:         merchantID,
			MerchantPrivateKey: keys.merchantPrivateBase64,
			PlatformPublicKey:  keys.platformPublicBase64,
		},
		TimestampSkewSeconds: 180,
	}

	provider, err := NewPluginsWorldProvider(cfg)
	if err != nil {
		t.Fatalf("new provider: %v", err)
	}

	resp, err := provider.CreatePayment(context.Background(), ProviderCreateRequest{
		OutTradeNo: "order_10001",
		Method:     methodJump,
		Channel:    ChannelAlipay,
		Amount:     "5.00",
		NotifyURL:  "https://example.com/api/v1/payments/notify",
		ReturnURL:  "https://example.com/api/v1/payments/return",
		ClientIP:   "127.0.0.1",
		Device:     "pc",
		Subject:    "Recharge",
		Param:      "order_10001",
	})
	if err != nil {
		t.Fatalf("create payment: %v", err)
	}
	if resp.TradeNo != "trade_10001" {
		t.Fatalf("trade_no mismatch: %s", resp.TradeNo)
	}
	if resp.PayType != "jump" {
		t.Fatalf("pay_type mismatch: %s", resp.PayType)
	}
	if resp.PayInfo != "https://pay.example.com/jump" {
		t.Fatalf("pay_info mismatch: %s", resp.PayInfo)
	}
}

func TestPluginsWorldProviderCreatePaymentErrorResponses(t *testing.T) {
	keys := newTestKeys(t)
	merchantID := int64(1001)

	t.Run("http_status_error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadGateway)
		}))
		t.Cleanup(server.Close)

		cfg := &Config{
			Enabled:       true,
			PublicBaseURL: "https://example.com",
			MinAmount:     5,
			MaxAmount:     5000,
			Step:          1,
			PluginsWorld: PluginsWorldConfig{
				APIBaseURL:         server.URL,
				MerchantID:         merchantID,
				MerchantPrivateKey: keys.merchantPrivateBase64,
				PlatformPublicKey:  keys.platformPublicBase64,
			},
			TimestampSkewSeconds: 180,
		}

		provider, err := NewPluginsWorldProvider(cfg)
		if err != nil {
			t.Fatalf("new provider: %v", err)
		}

		_, err = provider.CreatePayment(context.Background(), ProviderCreateRequest{
			OutTradeNo: "order_10002",
			Method:     methodJump,
			Channel:    ChannelWxpay,
			Amount:     "5.00",
			NotifyURL:  "https://example.com/api/v1/payments/notify",
			ReturnURL:  "https://example.com/api/v1/payments/return",
			ClientIP:   "127.0.0.1",
			Device:     "pc",
			Subject:    "Recharge",
		})
		if err == nil {
			t.Fatalf("expected error")
		}
	})

	t.Run("gateway_error_code", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			payload := pluginsWorldCreateResponse{
				Code:     1,
				Msg:      "bad request",
				Sign:     "ignored",
				SignType: "RSA",
			}
			_ = json.NewEncoder(w).Encode(payload)
		}))
		t.Cleanup(server.Close)

		cfg := &Config{
			Enabled:       true,
			PublicBaseURL: "https://example.com",
			MinAmount:     5,
			MaxAmount:     5000,
			Step:          1,
			PluginsWorld: PluginsWorldConfig{
				APIBaseURL:         server.URL,
				MerchantID:         merchantID,
				MerchantPrivateKey: keys.merchantPrivateBase64,
				PlatformPublicKey:  keys.platformPublicBase64,
			},
			TimestampSkewSeconds: 180,
		}

		provider, err := NewPluginsWorldProvider(cfg)
		if err != nil {
			t.Fatalf("new provider: %v", err)
		}
		_, err = provider.CreatePayment(context.Background(), ProviderCreateRequest{
			OutTradeNo: "order_10003",
			Method:     methodJump,
			Channel:    ChannelAlipay,
			Amount:     "5.00",
			NotifyURL:  "https://example.com/api/v1/payments/notify",
			ReturnURL:  "https://example.com/api/v1/payments/return",
			ClientIP:   "127.0.0.1",
			Device:     "pc",
			Subject:    "Recharge",
		})
		if err == nil {
			t.Fatalf("expected error")
		}
	})

	t.Run("invalid_response_sign", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			payload := pluginsWorldCreateResponse{
				Code:      0,
				Msg:       "ok",
				TradeNo:   "trade_10004",
				PayType:   "jump",
				PayInfo:   "https://pay.example.com/jump",
				Timestamp: "1710000001",
				Sign:      "invalid",
				SignType:  "RSA",
			}
			_ = json.NewEncoder(w).Encode(payload)
		}))
		t.Cleanup(server.Close)

		cfg := &Config{
			Enabled:       true,
			PublicBaseURL: "https://example.com",
			MinAmount:     5,
			MaxAmount:     5000,
			Step:          1,
			PluginsWorld: PluginsWorldConfig{
				APIBaseURL:         server.URL,
				MerchantID:         merchantID,
				MerchantPrivateKey: keys.merchantPrivateBase64,
				PlatformPublicKey:  keys.platformPublicBase64,
			},
			TimestampSkewSeconds: 180,
		}

		provider, err := NewPluginsWorldProvider(cfg)
		if err != nil {
			t.Fatalf("new provider: %v", err)
		}
		_, err = provider.CreatePayment(context.Background(), ProviderCreateRequest{
			OutTradeNo: "order_10004",
			Method:     methodJump,
			Channel:    ChannelAlipay,
			Amount:     "5.00",
			NotifyURL:  "https://example.com/api/v1/payments/notify",
			ReturnURL:  "https://example.com/api/v1/payments/return",
			ClientIP:   "127.0.0.1",
			Device:     "pc",
			Subject:    "Recharge",
		})
		if err == nil || !errors.Is(err, ErrSignatureInvalid) {
			t.Fatalf("expected signature invalid error, got %v", err)
		}
	})
}

func valuesToMap(values url.Values) map[string]string {
	params := make(map[string]string, len(values))
	for key, list := range values {
		if len(list) == 0 {
			continue
		}
		params[key] = strings.TrimSpace(list[0])
	}
	return params
}
