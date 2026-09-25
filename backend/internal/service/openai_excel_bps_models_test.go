package service

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

func TestExcelBPSModelSelection(t *testing.T) {
	a := excelAccount()
	require.True(t, a.IsExcelBPSEnabledForModel("gpt-6-sol"), "legacy all-model setting")
	a.Extra["openai_excel_bps_models"] = []any{"gpt-6-astra"}
	require.True(t, a.IsExcelBPSEnabledForModel("gpt-6-astra"))
	require.False(t, a.IsExcelBPSEnabledForModel("gpt-6-sol"))
	require.False(t, a.IsExcelBPSEnabledForModel("gpt-6-astra-other"))
	a.Credentials["model_mapping"] = map[string]any{"alias": "gpt-6-astra", "gpt-6-astra": "gpt-6-sol"}
	require.True(t, a.IsExcelBPSEnabledForModel("alias"))
	require.False(t, a.IsExcelBPSEnabledForModel("gpt-6-astra"), "selection matches mapped upstream")
	require.True(t, a.isExcelBPSUpstreamModelEnabled("gpt-6-astra"), "already mapped names must not map again")
	for _, models := range []any{[]any{}, []string{}, nil, "gpt-6-astra", []any{42, false}} {
		a.Extra["openai_excel_bps_models"] = models
		require.False(t, a.IsExcelBPSEnabledForModel("alias"))
		require.False(t, a.isExcelBPSAllModelsEnabled())
	}
	a.Extra["openai_excel_bps_models"] = []string{" gpt-6-astra "}
	require.True(t, a.IsExcelBPSEnabledForModel("alias"))
	a.Extra["openai_excel_bps"] = false
	require.False(t, a.IsExcelBPSEnabledForModel("alias"))
	var absent *Account
	require.False(t, absent.IsExcelBPSEnabledForModel("gpt-6-astra"))
}

func TestExcelBPSSelectedModelForwarding(t *testing.T) {
	for _, model := range []string{"gpt-6-astra", "gpt-6-sol"} {
		t.Run(model, func(t *testing.T) {
			wire := fmt.Sprintf("event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_test\",\"status\":\"completed\",\"model\":%q,\"output\":[],\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}\n\n", model)
			upstream := &httpUpstreamRecorder{resp: &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: io.NopCloser(strings.NewReader(wire))}}
			svc := openAIClientToolsTestService(upstream)
			a := excelAccount()
			a.Extra["openai_excel_bps_models"] = []string{"gpt-6-astra"}
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = httptest.NewRequest("POST", "/v1/responses", nil)
			result, err := svc.Forward(context.Background(), c, a, []byte(fmt.Sprintf(`{"model":%q,"stream":true,"input":"test"}`, model)))
			require.NoError(t, err)
			require.NotNil(t, result)
			require.NotNil(t, upstream.lastReq)
			if model == "gpt-6-astra" {
				require.Equal(t, "bps.openai.com", upstream.lastReq.URL.Host)
				require.Equal(t, "/basispoints/api/responses", upstream.lastReq.URL.Path)
			} else {
				require.Equal(t, "chatgpt.com", upstream.lastReq.URL.Host)
				require.Equal(t, "/backend-api/codex/responses", upstream.lastReq.URL.Path)
			}
		})
	}
}

func TestExcelBPSSelectedModelsPreserveCodexTransport(t *testing.T) {
	a := excelAccount()
	a.Extra["openai_excel_bps_models"] = []string{"gpt-6-astra"}
	a.Extra["openai_oauth_responses_websockets_v2_mode"] = OpenAIWSIngressModeCtxPool
	a.Extra["openai_oauth_responses_websockets_v2_enabled"] = true
	cfg := &config.Config{}
	cfg.Gateway.OpenAIWS.Enabled = true
	cfg.Gateway.OpenAIWS.OAuthEnabled = true
	cfg.Gateway.OpenAIWS.ResponsesWebsocketsV2 = true
	cfg.Gateway.OpenAIWS.ModeRouterV2Enabled = true
	svc := &OpenAIGatewayService{cfg: cfg}
	require.False(t, a.IsOpenAIWSForceHTTPEnabled())
	require.True(t, a.IsOpenAIResponsesWebSocketV2Enabled())
	require.Equal(t, OpenAIWSIngressModeCtxPool, a.ResolveOpenAIResponsesWebSocketV2Mode("off"))
	for _, transport := range []OpenAIUpstreamTransport{OpenAIUpstreamTransportResponsesWebsocketV2, OpenAIUpstreamTransportResponsesWebsocketV2Ingress} {
		require.False(t, svc.isOpenAIAccountTransportCompatible(a, transport, "gpt-6-astra"))
		require.True(t, svc.isOpenAIAccountTransportCompatible(a, transport, "gpt-6-sol"))
	}
	require.True(t, svc.isOpenAIAccountTransportCompatible(a, OpenAIUpstreamTransportHTTPSSE, "gpt-6-astra"))
}

func TestExcelBPSSelectedCompactKeepsExcelModel(t *testing.T) {
	a := excelAccount()
	a.Extra["openai_excel_bps_models"] = []string{"gpt-6-astra"}
	a.Credentials["model_mapping"] = map[string]any{"alias": "gpt-6-astra"}
	a.Credentials["compact_model_mapping"] = map[string]any{"alias": "gpt-6-sol"}
	require.Equal(t, "gpt-6-astra", resolveOpenAIAccountUpstreamModelForRequest(a, "alias", true))
}

func TestExcelBPSModelAliasesRouteAndRewriteUpstreamModel(t *testing.T) {
	a := excelAccount()
	a.Extra["openai_excel_bps_models"] = []any{"gpt-6-astra", "gpt-5.6-sol", "gpt-5.6-luna"}
	a.Extra["openai_excel_bps_model_aliases"] = map[string]any{
		"gpt-6-sol":  "gpt-5.6-sol",
		"gpt-6-luna": "gpt-5.6-luna",
	}

	// Aliased names select BPS and resolve to the upstream model.
	require.True(t, a.IsExcelBPSEnabledForModel("gpt-6-sol"))
	require.Equal(t, "gpt-5.6-sol", a.ExcelBPSUpstreamModel("gpt-6-sol"))
	require.True(t, a.IsExcelBPSEnabledForModel("gpt-6-luna"))
	require.Equal(t, "gpt-5.6-luna", a.ExcelBPSUpstreamModel("gpt-6-luna"))
	// Unaliased names keep working, and models outside the list stay on Codex.
	require.True(t, a.IsExcelBPSEnabledForModel("gpt-6-astra"))
	require.Equal(t, "gpt-5.6-sol", a.ExcelBPSUpstreamModel("gpt-5.6-sol"))
	require.False(t, a.IsExcelBPSEnabledForModel("gpt-5.5"))
	require.Equal(t, "gpt-5.5", a.ExcelBPSUpstreamModel("gpt-5.5"))
	// Account-level model mapping still runs first.
	a.Credentials["model_mapping"] = map[string]any{"alias-sol": "gpt-6-sol"}
	require.True(t, a.IsExcelBPSEnabledForModel("alias-sol"))
	require.Equal(t, "gpt-5.6-sol", a.ExcelBPSUpstreamModel("alias-sol"))
	// The scheduler resolves the same upstream model.
	require.Equal(t, "gpt-5.6-luna", resolveOpenAIAccountUpstreamModelForRequest(a, "gpt-6-luna", false))

	// Disabling the Excel / BPS protocol removes the alias from routing entirely.
	a.Extra["openai_excel_bps"] = false
	require.False(t, a.IsExcelBPSEnabledForModel("gpt-6-sol"))
	require.Equal(t, "gpt-6-sol", a.ExcelBPSUpstreamModel("gpt-6-sol"))
}

func TestExcelBPSForwardRewritesAliasedModelForUpstream(t *testing.T) {
	gin.SetMode(gin.TestMode)
	wire := "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_alias\",\"status\":\"completed\",\"model\":\"gpt-5.6-sol\",\"output\":[{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"21\"}]}],\"usage\":{\"input_tokens\":10,\"output_tokens\":2}}}\n\n"
	upstream := &httpUpstreamRecorder{resp: &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: io.NopCloser(strings.NewReader(wire))}}
	svc := openAIClientToolsTestService(upstream)

	a := excelAccount()
	a.Extra["openai_excel_bps_models"] = []any{"gpt-6-astra", "gpt-5.6-sol", "gpt-5.6-luna"}
	a.Extra["openai_excel_bps_model_aliases"] = map[string]any{"gpt-6-sol": "gpt-5.6-sol"}

	body := []byte(`{"model":"gpt-6-sol","stream":false,"store":false,"input":"test"}`)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(string(body)))

	result, err := svc.Forward(context.Background(), c, a, body)
	require.NoError(t, err)
	require.Equal(t, "gpt-5.6-sol", gjson.GetBytes(upstream.lastBody, "model").String(),
		"the aliased model must be what the BPS upstream receives")
	require.Equal(t, "gpt-6-sol", result.Model, "the client-visible model name is preserved")
	require.Equal(t, "gpt-5.6-sol", result.UpstreamModel)
}
