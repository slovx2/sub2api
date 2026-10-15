package service

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/google/uuid"
)

type devinLoginSession struct {
	verifier, proxyURL string
	created            time.Time
}
type DevinOAuthService struct {
	mu        sync.Mutex
	sessions  map[string]devinLoginSession
	proxyRepo ProxyRepository
	upstream  HTTPUpstream
}

func NewDevinOAuthService(proxyRepo ProxyRepository, upstream HTTPUpstream) *DevinOAuthService {
	return &DevinOAuthService{sessions: map[string]devinLoginSession{}, proxyRepo: proxyRepo, upstream: upstream}
}

// GenerateAuthURL 沿用 CPA 的无回调端口 PKCE 流程，适合远程服务器上的管理后台。
func (s *DevinOAuthService) GenerateAuthURL(ctx context.Context, proxyID *int64) (map[string]string, error) {
	proxyURL := ""
	if proxyID != nil {
		proxy, err := s.proxyRepo.GetByID(ctx, *proxyID)
		if err != nil {
			return nil, err
		}
		if proxy == nil {
			return nil, fmt.Errorf("proxy not found")
		}
		proxyURL = proxy.URL()
	}
	var random [64]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, err
	}
	verifier := base64.RawURLEncoding.EncodeToString(random[:])
	digest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	id := uuid.NewString()
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, session := range s.sessions {
		if time.Since(session.created) > 10*time.Minute {
			delete(s.sessions, key)
		}
	}
	if len(s.sessions) >= 128 {
		return nil, infraerrors.New(http.StatusTooManyRequests, "DEVIN_LOGIN_LIMIT", "Too many pending Devin logins")
	}
	s.sessions[id] = devinLoginSession{verifier: verifier, proxyURL: proxyURL, created: time.Now()}
	authURL := "https://app.devin.ai/auth/cli/continue?state=" + url.QueryEscape(id) + "&prompt=select_account&code_challenge=" + url.QueryEscape(challenge) + "&code_challenge_method=S256&cli_pkce_marker=1"
	return map[string]string{"auth_url": authURL, "session_id": id}, nil
}

func (s *DevinOAuthService) ExchangeCode(ctx context.Context, sessionID, code string) (map[string]string, error) {
	s.mu.Lock()
	session, ok := s.sessions[sessionID]
	delete(s.sessions, sessionID)
	s.mu.Unlock()
	if !ok || time.Since(session.created) > 10*time.Minute {
		return nil, infraerrors.New(http.StatusBadRequest, "DEVIN_LOGIN_EXPIRED", "Devin login expired; generate a new authorization URL")
	}
	code = strings.TrimSpace(code)
	if code == "" || len(code) > 16384 {
		return nil, infraerrors.New(http.StatusBadRequest, "DEVIN_CODE_INVALID", "Invalid Devin authorization code")
	}
	// 只接收官方页面显示的授权码；不把任意回调 URL 或令牌当成 code 转发。
	if strings.Contains(code, "://") || strings.HasPrefix(code, "devin-session-token$") {
		return nil, infraerrors.New(http.StatusBadRequest, "DEVIN_CODE_INVALID", "Paste the authorization code shown by Devin")
	}
	body, _ := json.Marshal(map[string]string{"code": code, "code_verifier": session.verifier})
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.devin.ai/auth/cli/token", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := s.upstream.Do(req, session.proxyURL, 0, 1)
	if err != nil {
		return nil, infraerrors.New(http.StatusBadGateway, "DEVIN_EXCHANGE_FAILED", "Failed to contact Devin authorization service")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, infraerrors.New(http.StatusBadGateway, "DEVIN_EXCHANGE_FAILED", "Devin rejected the authorization code; generate a new login URL")
	}
	var result struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&result); err != nil {
		return nil, infraerrors.New(http.StatusBadGateway, "DEVIN_TOKEN_INVALID", "Invalid Devin token response")
	}
	token := strings.TrimSpace(result.Token)
	if strings.HasPrefix(token, "eyJ") {
		token = "devin-session-token$" + token
	}
	credentials := map[string]any{"session_token": token}
	if err := validateDevinCredentials(AccountTypeOAuth, credentials); err != nil {
		return nil, infraerrors.New(http.StatusBadGateway, "DEVIN_TOKEN_INVALID", "Invalid Devin session token")
	}
	return map[string]string{"session_token": token}, nil
}
