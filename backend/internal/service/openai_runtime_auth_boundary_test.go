package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestOpenAIRequestBuildersDoNotMixRuntimeProofWithSelectedCredential(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, transport := range []string{"http", "passthrough", "websocket"} {
		t.Run(transport, func(t *testing.T) {
			account := &Account{
				Platform: PlatformOpenAI,
				Type:     AccountTypeAPIKey,
				Credentials: map[string]any{
					"api_key":                    "selected-upstream-key",
					credKeyHeaderOverrideEnabled: true,
					// 模拟禁用名单扩充前已保存的配置，出站也必须过滤。
					credKeyHeaderOverrides: map[string]any{
						"X-OpenAI-Agent-Assertion": "stale-runtime-proof",
						"OpenAI-Organization":      "selected-org",
						"OpenAI-Project":           "selected-project",
					},
				},
			}
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
			c.Request.Header.Set("Authorization", "Bearer gateway-key")
			c.Request.Header.Set("X-OpenAI-Agent-Assertion", "client-runtime-proof")
			c.Request.Header.Set("ChatGPT-Account-ID", "client-account")
			c.Request.Header.Set("OpenAI-Organization", "client-org")
			c.Request.Header.Set("OpenAI-Project", "client-project")
			body := []byte(`{"model":"gpt-5.4","input":[]}`)
			svc := &OpenAIGatewayService{}
			var headers http.Header
			switch transport {
			case "http":
				req, err := svc.buildUpstreamRequest(context.Background(), c, account, body, "selected-upstream-key", false, "", true)
				require.NoError(t, err)
				headers = req.Header
			case "passthrough":
				req, err := svc.buildUpstreamRequestOpenAIPassthrough(context.Background(), c, account, body, "selected-upstream-key")
				require.NoError(t, err)
				headers = req.Header
			case "websocket":
				var err error
				headers, _, err = svc.buildOpenAIWSHeaders(context.Background(), c, account, "selected-upstream-key",
					OpenAIWSProtocolDecision{Transport: OpenAIUpstreamTransportResponsesWebsocketV2}, true, "", "", "", "", "")
				require.NoError(t, err)
			}
			require.Equal(t, "Bearer selected-upstream-key", headers.Get("Authorization"))
			for name := range headers {
				require.False(t, strings.EqualFold(name, "x-openai-agent-assertion"), "不得混入其他 runtime 的证明")
			}
			require.Empty(t, headers.Get("ChatGPT-Account-ID"))
			// API Key 的合法组织和项目配置仍然保留。
			require.Equal(t, "selected-org", getHeaderRaw(headers, "openai-organization"))
			require.Equal(t, "selected-project", getHeaderRaw(headers, "openai-project"))
		})
	}
}

func TestSetOpenAIChatGPTAccountHeadersClearsPreviousAccount(t *testing.T) {
	headers := make(http.Header)
	setOpenAIChatGPTAccountHeaders(headers, &Account{
		Platform: PlatformOpenAI,
		Type:     AccountTypeOAuth,
		Credentials: map[string]any{
			"chatgpt_account_id":         "previous-account",
			"chatgpt_account_is_fedramp": true,
		},
	})
	headers["CHATGPT-ACCOUNT-ID"] = []string{"noncanonical-previous-account"}
	headers["x-openai-fedramp"] = []string{"true"}
	setOpenAIChatGPTAccountHeaders(headers, &Account{
		Platform: PlatformOpenAI,
		Type:     AccountTypeOAuth,
	})
	require.Empty(t, headers.Get("ChatGPT-Account-ID"), "凭据缺少账号 ID 时不能沿用其他账号")
	require.Empty(t, headers.Get("X-OpenAI-Fedramp"))
	require.Empty(t, headers)
	setOpenAIChatGPTAccountHeaders(headers, &Account{
		Platform: PlatformOpenAI,
		Type:     AccountTypeOAuth,
		Credentials: map[string]any{
			"chatgpt_account_id": "next-account",
		},
	})
	require.Equal(t, http.Header{"Chatgpt-Account-Id": []string{"next-account"}}, headers)
}
