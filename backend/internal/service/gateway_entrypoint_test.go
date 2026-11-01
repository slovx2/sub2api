package service

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

func TestAnthropicEntrypointOutbound(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, kind := range []string{AccountTypeOAuth, AccountTypeSetupToken, AccountTypeAPIKey} {
		for _, mode := range []string{"", "passthrough", "cli", "sdk-ts"} {
			for _, source := range []string{"claude_code", "third_party"} {
				for _, endpoint := range []string{"messages", "stream", "count_tokens", "apikey_passthrough", "apikey_count_tokens"} {
					if kind != AccountTypeAPIKey && (endpoint == "apikey_passthrough" || endpoint == "apikey_count_tokens") {
						continue
					}
					t.Run(kind+"/"+mode+"/"+source+"/"+endpoint, func(t *testing.T) {
						resetGatewayForwardingSettingsCacheForTest(t)
						ctx := context.Background()
						c, _ := gin.CreateTestContext(httptest.NewRecorder())
						c.Request = httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
						originalUA := "claude-cli/2.1.260 (external, sdk-cli, agent-sdk/0.3.0)"
						c.Request.Header.Set("User-Agent", originalUA)
						account := &Account{ID: 1, Platform: PlatformAnthropic, Type: kind,
							Extra: map[string]any{anthropicClientEntrypointKey: mode}}
						svc := &GatewayService{cfg: &config.Config{}, identityService: NewIdentityService(&stubIdentityCache{
							fingerprint: &Fingerprint{UserAgent: originalUA, ClientID: "test-client", UpdatedAt: time.Now().Unix()},
						})}
						body := []byte(`{"model":"claude-haiku-4-5","system":[{"type":"text","text":"x-anthropic-billing-header: cc_version=2.1.260; cc_entrypoint=sdk-cli;"},{"type":"text","text":"You are Claude Code."}],"messages":[{"role":"user","content":"hello"}],"stream":true}`)
						mimic := source == "third_party" && account.IsOAuth()
						if source == "third_party" {
							c.Request.Header.Set("User-Agent", "third-party/1.0")
							body = []byte(`{"model":"claude-haiku-4-5","messages":[{"role":"user","content":"hello"}],"stream":true}`)
							if mimic {
								body = svc.applyClaudeCodeOAuthMimicryToBody(ctx, c, account, body, nil, "claude-haiku-4-5")
							}
						}
						build := func() (*http.Request, []byte) {
							t.Helper()
							tokenType := "oauth"
							if kind == AccountTypeAPIKey {
								tokenType = "apikey"
							}
							var req *http.Request
							var wire []byte
							var err error
							switch endpoint {
							case "count_tokens":
								req, wire, err = svc.buildCountTokensRequest(ctx, c, account, body, "test-token", tokenType, "claude-haiku-4-5", mimic)
							case "apikey_passthrough":
								req, wire, err = svc.buildUpstreamRequestAnthropicAPIKeyPassthrough(ctx, c, account, body, "test-token")
							case "apikey_count_tokens":
								req, err = svc.buildCountTokensRequestAnthropicAPIKeyPassthrough(ctx, c, account, body, "test-token")
							default:
								req, wire, err = svc.buildUpstreamRequest(ctx, c, account, body, "test-token", tokenType, "claude-haiku-4-5", endpoint == "stream", mimic)
							}
							require.NoError(t, err)
							actual, err := io.ReadAll(req.Body)
							require.NoError(t, err)
							require.NoError(t, req.Body.Close())
							require.Equal(t, int64(len(actual)), req.ContentLength)
							if wire != nil {
								require.Equal(t, wire, actual)
							}
							return req, actual
						}
						delete(account.Extra, anthropicClientEntrypointKey)
						baselineReq, baselineBody := build()
						account.Extra[anthropicClientEntrypointKey] = mode
						req, wire := build()
						if mode == "" || mode == "passthrough" {
							require.Equal(t, baselineBody, wire)
							require.Equal(t, getHeaderRaw(baselineReq.Header, "User-Agent"), getHeaderRaw(req.Header, "User-Agent"))
						} else {
							require.Contains(t, getHeaderRaw(req.Header, "User-Agent"), "external, "+mode)
							if source == "third_party" && !mimic {
								require.False(t, gjson.GetBytes(wire, "system").Exists())
							} else {
								require.Contains(t, gjson.GetBytes(wire, "system.0.text").String(), "cc_entrypoint="+mode+";")
							}
						}
					})
				}
			}
		}
	}
}

func TestAnthropicEntrypointBoundaries(t *testing.T) {
	body := []byte(`{"system":[{"type":"text","text":"normal cc_entrypoint=sdk-cli;"},{"type":"text","text":"x-anthropic-billing-header: cc_version=2.1.260;"}]}`)
	account := &Account{Platform: PlatformAnthropic, Type: AccountTypeOAuth, Extra: map[string]any{anthropicClientEntrypointKey: "sdk-ts"}}
	result := rewriteAnthropicEntrypointBody(body, account)
	require.Equal(t, "normal cc_entrypoint=sdk-cli;", gjson.GetBytes(result, "system.0.text").String())
	require.Contains(t, gjson.GetBytes(result, "system.1.text").String(), "cc_entrypoint=sdk-ts;")
	require.Equal(t, result, rewriteAnthropicEntrypointBody(result, account))
	for _, raw := range []string{`{}`, `{"system":"text"}`, `{"system":[{"type":"text","text":"ordinary"}]}`} {
		require.Equal(t, raw, string(rewriteAnthropicEntrypointBody([]byte(raw), account)))
	}
	for _, ua := range []string{"", "third-party/1.0", "claude-cli/2.1.260", "claude-cli/2.1.260 (external, sdk-cli, agent-sdk/0.3.0)"} {
		header := http.Header{"User-Agent": {ua}}
		applyAnthropicEntrypointHeader(header, account)
		require.Contains(t, getHeaderRaw(header, "User-Agent"), "external, sdk-ts")
		if ua == "claude-cli/2.1.260 (external, sdk-cli, agent-sdk/0.3.0)" {
			require.Equal(t, "claude-cli/2.1.260 (external, sdk-ts, agent-sdk/0.3.0)", getHeaderRaw(header, "User-Agent"))
		}
	}
	for _, unsupported := range []*Account{nil, {Platform: PlatformOpenAI, Type: AccountTypeOAuth, Extra: account.Extra},
		{Platform: PlatformAnthropic, Type: AccountTypeServiceAccount, Extra: account.Extra},
		{Platform: PlatformAnthropic, Type: AccountTypeOAuth, Extra: map[string]any{anthropicClientEntrypointKey: "invalid"}}} {
		require.Equal(t, body, rewriteAnthropicEntrypointBody(body, unsupported))
		header := http.Header{"User-Agent": {"unchanged"}}
		applyAnthropicEntrypointHeader(header, unsupported)
		require.Equal(t, "unchanged", getHeaderRaw(header, "User-Agent"))
	}
}
