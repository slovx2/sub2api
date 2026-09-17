package service

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/tlsfingerprint"
	"github.com/stretchr/testify/require"
)

// usageWindowsHTTPUpstream 固定返回一段窗口响应（或指定状态码），并记录请求。
type usageWindowsHTTPUpstream struct {
	status   int
	body     string
	calls    int
	lastURL  string
	lastAuth string
}

func (u *usageWindowsHTTPUpstream) Do(req *http.Request, _ string, _ int64, _ int) (*http.Response, error) {
	u.calls++
	u.lastURL = req.URL.String()
	u.lastAuth = req.Header.Get("Authorization")
	body := u.body
	if body == "" {
		body = "{}"
	}
	return &http.Response{
		StatusCode: u.status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}, nil
}

func (u *usageWindowsHTTPUpstream) DoWithTLS(req *http.Request, proxyURL string, accountID int64, concurrency int, _ *tlsfingerprint.Profile) (*http.Response, error) {
	return u.Do(req, proxyURL, accountID, concurrency)
}

// usageWindowsAccountRepo 只实现额度探测用到的方法，记录 UpdateExtra 落库内容。
type usageWindowsAccountRepo struct {
	AccountRepository
	account     *Account
	updates     map[string]any
	updateCalls int
}

func (r *usageWindowsAccountRepo) GetByID(context.Context, int64) (*Account, error) {
	return r.account, nil
}

func (r *usageWindowsAccountRepo) UpdateExtra(_ context.Context, _ int64, updates map[string]any) error {
	r.updateCalls++
	r.updates = updates
	return nil
}

func usageWindowsTestAccount(baseURL string) *Account {
	return &Account{
		ID:       7,
		Platform: PlatformDeepseek,
		Type:     AccountTypeAPIKey,
		Status:   StatusActive,
		Credentials: map[string]any{
			"api_key":      "sk-test",
			"base_url":     baseURL,
			"account_mode": AccountModePayG,
		},
	}
}

// 白名单关闭 + 允许 http：与线上默认一致（自定义中转多为内网 http 地址）。
func usageWindowsTestConfig() *config.Config {
	return &config.Config{
		Security: config.SecurityConfig{
			URLAllowlist: config.URLAllowlistConfig{Enabled: false, AllowInsecureHTTP: true},
		},
	}
}

func TestParseUsageWindows(t *testing.T) {
	body := []byte(`{
	  "object": "usage_windows",
	  "is_available": true,
	  "windows": [
	    {"window":"5h","used":0.75,"limit":3,"used_percent":25,"reset_at":"2026-09-17T18:18:17.956Z"},
	    {"window":"weekly","used":3,"limit":6,"used_percent":"50","reset_at":"2026-09-24T13:18:17Z"}
	  ],
	  "balance": {"currency":"USD","total":9.97}
	}`)

	tiers := parseUsageWindows(body)
	require.Len(t, tiers, 2)
	require.Equal(t, "5h", tiers[0].Window)
	require.Equal(t, 25.0, tiers[0].UsedPercent)
	require.Equal(t, "2026-09-17T18:18:17Z", tiers[0].ResetAt)
	require.Equal(t, "weekly", tiers[1].Window)
	require.Equal(t, 50.0, tiers[1].UsedPercent, "百分比允许字符串形态")
}

func TestParseUsageWindowsSkipsInvalidEntries(t *testing.T) {
	body := []byte(`{"windows":[
	  {"window":"monthly","used_percent":10},
	  {"window":"5h"},
	  {"window":"weekly","used_percent":12.5}
	]}`)

	tiers := parseUsageWindows(body)
	require.Len(t, tiers, 1)
	require.Equal(t, "weekly", tiers[0].Window)
	require.Equal(t, 12.5, tiers[0].UsedPercent)
}

func TestParseUsageWindowsMissingField(t *testing.T) {
	require.Empty(t, parseUsageWindows([]byte(`{"object":"usage_windows"}`)))
	require.Empty(t, parseUsageWindows([]byte(`not json`)))
}

func TestIsOfficialCNUsageBaseURL(t *testing.T) {
	require.True(t, isOfficialCNUsageBaseURL("https://api.deepseek.com/v1"))
	require.True(t, isOfficialCNUsageBaseURL("https://api.moonshot.cn/v1"))
	require.True(t, isOfficialCNUsageBaseURL("https://relay.api.z.ai/v1"), "子域同样视为官方")
	require.False(t, isOfficialCNUsageBaseURL("http://commandcode-proxy:3050/v1"))
	require.False(t, isOfficialCNUsageBaseURL(""))
}

// 上游 404：标记 Unsupported、不写快照、不报错 —— 管理端据此隐藏窗口单元格。
func TestQueryUsageWindowsUnsupportedOnNotFound(t *testing.T) {
	upstream := &usageWindowsHTTPUpstream{status: http.StatusNotFound, body: `{"error":"not found"}`}
	repo := &usageWindowsAccountRepo{account: usageWindowsTestAccount("http://relay.local/v1")}
	svc := NewCNProviderQuotaService(repo, nil, upstream, usageWindowsTestConfig())

	result, err := svc.queryUsageWindows(context.Background(), repo.account)
	require.NoError(t, err)
	require.True(t, result.Unsupported)
	require.False(t, result.Success)
	require.Empty(t, result.Tiers)
	require.Zero(t, repo.updateCalls, "不支持时不得落快照")
	require.Equal(t, "http://relay.local/v1/usage/windows", upstream.lastURL)
	require.Equal(t, "Bearer sk-test", upstream.lastAuth)
}

// 上游 200：解析窗口并落 provider 维度的快照键（与前端/阈值评估共用）。
func TestQueryUsageWindowsPersistsSnapshot(t *testing.T) {
	upstream := &usageWindowsHTTPUpstream{
		status: http.StatusOK,
		body: `{"object":"usage_windows","windows":[
		  {"window":"5h","used":1.5,"limit":3,"used_percent":50,"reset_at":"2026-09-17T18:18:17Z"},
		  {"window":"weekly","used":1.5,"limit":6,"used_percent":25,"reset_at":"2026-09-24T13:18:17Z"}
		]}`,
	}
	repo := &usageWindowsAccountRepo{account: usageWindowsTestAccount("http://relay.local/v1")}
	svc := NewCNProviderQuotaService(repo, nil, upstream, usageWindowsTestConfig())

	result, err := svc.queryUsageWindows(context.Background(), repo.account)
	require.NoError(t, err)
	require.True(t, result.Success)
	require.True(t, result.Persisted)
	require.Len(t, result.Tiers, 2)
	require.Equal(t, cnUsageWindowsSource, result.Source)
	require.Equal(t, 1, repo.updateCalls)
	require.Equal(t, 50.0, repo.updates["deepseek_5h_used_percent"])
	require.Equal(t, 25.0, repo.updates["deepseek_weekly_used_percent"])
	require.Equal(t, "2026-09-17T18:18:17Z", repo.updates["deepseek_5h_reset_at"])
	require.NotEmpty(t, repo.updates["deepseek_usage_updated_at"])
}

// 官方主机：不实现通用窗口规范，直接判不支持且不发请求。
func TestQueryUsageWindowsSkipsOfficialHost(t *testing.T) {
	upstream := &usageWindowsHTTPUpstream{status: http.StatusOK, body: `{"windows":[]}`}
	repo := &usageWindowsAccountRepo{account: usageWindowsTestAccount("https://api.deepseek.com")}
	svc := NewCNProviderQuotaService(repo, nil, upstream, usageWindowsTestConfig())

	result, err := svc.queryUsageWindows(context.Background(), repo.account)
	require.NoError(t, err)
	require.True(t, result.Unsupported)
	require.Zero(t, upstream.calls, "不得对官方 API 发无意义探测")
	require.Zero(t, repo.updateCalls)
}

// 401/403：如实上报鉴权失败（不写成 Unsupported，管理端需要提示）。
func TestQueryUsageWindowsAuthFailure(t *testing.T) {
	upstream := &usageWindowsHTTPUpstream{status: http.StatusUnauthorized}
	repo := &usageWindowsAccountRepo{account: usageWindowsTestAccount("http://relay.local/v1")}
	svc := NewCNProviderQuotaService(repo, nil, upstream, usageWindowsTestConfig())

	result, err := svc.queryUsageWindows(context.Background(), repo.account)
	require.NoError(t, err)
	require.False(t, result.Unsupported)
	require.Contains(t, result.Error, "Authentication failed")
	require.Zero(t, repo.updateCalls)
}
