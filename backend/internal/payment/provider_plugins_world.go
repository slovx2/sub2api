package payment

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

type PluginsWorldProvider struct {
	enabled    bool
	apiBaseURL string
	merchantID int64
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	httpClient *http.Client
}

type pluginsWorldCreateResponse struct {
	Code      int    `json:"code"`
	Msg       string `json:"msg"`
	TradeNo   string `json:"trade_no"`
	PayType   string `json:"pay_type"`
	PayInfo   string `json:"pay_info"`
	Timestamp string `json:"timestamp"`
	Sign      string `json:"sign"`
	SignType  string `json:"sign_type"`
}

func NewPluginsWorldProvider(cfg *Config) (Provider, error) {
	provider := &PluginsWorldProvider{
		enabled: false,
	}
	if cfg == nil {
		return provider, nil
	}
	if !cfg.Enabled {
		return provider, nil
	}

	privateKey, err := parseRSAPrivateKey(cfg.PluginsWorld.MerchantPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("parse merchant private key: %w", err)
	}
	publicKey, err := parseRSAPublicKey(cfg.PluginsWorld.PlatformPublicKey)
	if err != nil {
		return nil, fmt.Errorf("parse platform public key: %w", err)
	}

	provider.enabled = true
	provider.apiBaseURL = strings.TrimRight(cfg.PluginsWorld.APIBaseURL, "/")
	provider.merchantID = cfg.PluginsWorld.MerchantID
	provider.privateKey = privateKey
	provider.publicKey = publicKey
	provider.httpClient = &http.Client{Timeout: 15 * time.Second}
	return provider, nil
}

func (p *PluginsWorldProvider) CreatePayment(ctx context.Context, req ProviderCreateRequest) (*ProviderCreateResponse, error) {
	if !p.enabled {
		return nil, ErrPaymentDisabled
	}
	params := map[string]string{
		"pid":          strconv.FormatInt(p.merchantID, 10),
		"method":       req.Method,
		"type":         req.Channel,
		"out_trade_no": req.OutTradeNo,
		"notify_url":   req.NotifyURL,
		"return_url":   req.ReturnURL,
		"name":         req.Subject,
		"money":        req.Amount,
		"clientip":     req.ClientIP,
		"timestamp":    strconv.FormatInt(time.Now().Unix(), 10),
		"sign_type":    "RSA",
	}
	if req.Device != "" {
		params["device"] = req.Device
	}
	if req.Param != "" {
		params["param"] = req.Param
	}

	sign, err := p.sign(params)
	if err != nil {
		return nil, err
	}
	params["sign"] = sign

	values := url.Values{}
	for key, value := range params {
		if value == "" {
			continue
		}
		values.Set(key, value)
	}

	endpoint := p.apiBaseURL + "/api/pay/create"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("payment gateway returned status %d", resp.StatusCode)
	}

	var payload pluginsWorldCreateResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	if payload.Code != 0 {
		return nil, fmt.Errorf("payment gateway error: %s", payload.Msg)
	}
	if strings.TrimSpace(payload.Sign) == "" {
		return nil, ErrSignatureInvalid
	}

	respParams := map[string]string{
		"code":      strconv.Itoa(payload.Code),
		"msg":       payload.Msg,
		"trade_no":  payload.TradeNo,
		"pay_type":  payload.PayType,
		"pay_info":  payload.PayInfo,
		"timestamp": payload.Timestamp,
		"sign_type": payload.SignType,
	}
	if err := p.VerifySign(respParams, payload.Sign); err != nil {
		return nil, err
	}

	return &ProviderCreateResponse{
		TradeNo: payload.TradeNo,
		PayType: payload.PayType,
		PayInfo: payload.PayInfo,
	}, nil
}

func (p *PluginsWorldProvider) VerifySign(params map[string]string, sign string) error {
	if !p.enabled {
		return ErrPaymentDisabled
	}
	if strings.TrimSpace(sign) == "" {
		return ErrSignatureInvalid
	}
	content := buildSignContent(params)
	signature, err := base64.StdEncoding.DecodeString(sign)
	if err != nil {
		return ErrSignatureInvalid
	}
	checksum := sha256.Sum256([]byte(content))
	if err := rsa.VerifyPKCS1v15(p.publicKey, crypto.SHA256, checksum[:], signature); err != nil {
		return ErrSignatureInvalid
	}
	return nil
}

func (p *PluginsWorldProvider) sign(params map[string]string) (string, error) {
	if p.privateKey == nil {
		return "", errors.New("missing private key")
	}
	content := buildSignContent(params)
	checksum := sha256.Sum256([]byte(content))
	signature, err := rsa.SignPKCS1v15(rand.Reader, p.privateKey, crypto.SHA256, checksum[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}

func buildSignContent(params map[string]string) string {
	keys := make([]string, 0, len(params))
	for key, value := range params {
		if value == "" {
			continue
		}
		switch key {
		case "sign", "sign_type":
			continue
		default:
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)

	pairs := make([]string, 0, len(keys))
	for _, key := range keys {
		pairs = append(pairs, key+"="+params[key])
	}
	return strings.Join(pairs, "&")
}

func parseRSAPrivateKey(raw string) (*rsa.PrivateKey, error) {
	keyBytes, err := decodeKeyBytes(raw)
	if err != nil {
		return nil, errors.New("invalid private key")
	}
	if key, err := x509.ParsePKCS1PrivateKey(keyBytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(keyBytes)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not RSA")
	}
	return rsaKey, nil
}

func parseRSAPublicKey(raw string) (*rsa.PublicKey, error) {
	keyBytes, err := decodeKeyBytes(raw)
	if err != nil {
		return nil, errors.New("invalid public key")
	}
	parsed, err := x509.ParsePKIXPublicKey(keyBytes)
	if err == nil {
		if rsaKey, ok := parsed.(*rsa.PublicKey); ok {
			return rsaKey, nil
		}
	}
	if rsaKey, err := x509.ParsePKCS1PublicKey(keyBytes); err == nil {
		return rsaKey, nil
	}
	return nil, errors.New("public key is not RSA")
}

func decodeKeyBytes(raw string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("empty key")
	}
	if block, _ := pem.Decode([]byte(raw)); block != nil {
		return block.Bytes, nil
	}
	normalized := stripPemHeaders(raw)
	normalized = removeWhitespace(normalized)
	if normalized == "" {
		return nil, errors.New("empty key")
	}
	return base64.StdEncoding.DecodeString(normalized)
}

func stripPemHeaders(raw string) string {
	headers := []string{
		"-----BEGIN PRIVATE KEY-----",
		"-----END PRIVATE KEY-----",
		"-----BEGIN RSA PRIVATE KEY-----",
		"-----END RSA PRIVATE KEY-----",
		"-----BEGIN PUBLIC KEY-----",
		"-----END PUBLIC KEY-----",
		"-----BEGIN RSA PUBLIC KEY-----",
		"-----END RSA PUBLIC KEY-----",
	}
	for _, header := range headers {
		raw = strings.ReplaceAll(raw, header, "")
	}
	return raw
}

func removeWhitespace(raw string) string {
	buf := make([]byte, 0, len(raw))
	for i := 0; i < len(raw); i++ {
		switch raw[i] {
		case ' ', '\n', '\r', '\t':
			continue
		default:
			buf = append(buf, raw[i])
		}
	}
	return string(buf)
}
