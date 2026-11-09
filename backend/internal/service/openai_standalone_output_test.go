package service

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

func TestStandaloneOutputNamespaceRoutingBoundaries(t *testing.T) {
	body := []byte(`{"input":[{"type":"function_call_output","name":"external_event","namespace":"codex_app","output":"event"}]}`)
	cases := []struct {
		name        string
		account     *Account
		compact     bool
		declaration bool
		keep        bool
	}{
		{"oauth", &Account{Platform: PlatformOpenAI, Type: AccountTypeOAuth}, false, false, true},
		{"oauth_compact", &Account{Platform: PlatformOpenAI, Type: AccountTypeOAuth}, true, false, false},
		{"oauth_explicit_flatten", &Account{Platform: PlatformOpenAI, Type: AccountTypeOAuth, Extra: map[string]any{"openai_responses_flatten_namespaces": true}}, false, false, false},
		{"api_key_standard", &Account{Platform: PlatformOpenAI, Type: AccountTypeAPIKey}, false, false, false},
		{"api_key_namespace_tools", &Account{Platform: PlatformOpenAI, Type: AccountTypeAPIKey}, false, true, true},
		{"anthropic", &Account{Platform: PlatformAnthropic, Type: AccountTypeAPIKey}, false, false, false},
		{"gemini", &Account{Platform: PlatformGemini, Type: AccountTypeAPIKey}, false, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request := body
			if tc.declaration {
				request = []byte(`{"tools":[{"type":"namespace","name":"test","tools":[]}],"input":[{"type":"function_call_output","name":"external_event","namespace":"codex_app","output":"event"}]}`)
			}
			keep := shouldKeepOpenAIResponsesToolCallNamespaces(tc.account, OpenAIUpstreamTransportHTTPSSE, false, tc.compact, request)
			require.Equal(t, tc.keep, keep)
			if !shouldStripOpenAIResponsesInputNamespaces(tc.account, OpenAIUpstreamTransportHTTPSSE, false) {
				require.NotEqual(t, PlatformOpenAI, tc.account.Platform)
				return
			}
			forwarded, err := stripOpenAIResponsesInputNamespaces(request, keep)
			require.NoError(t, err)
			require.Equal(t, tc.keep, gjson.GetBytes(forwarded, "input.0.namespace").Exists())
		})
	}
}

func TestFilterCodexInputPreservesStandaloneAndPairedOutputs(t *testing.T) {
	for _, preserve := range []bool{false, true} {
		input := []any{
			map[string]any{"type": "function_call_output", "id": "fco_event", "name": "external_event", "namespace": "codex_app", "output": "event"},
			map[string]any{"type": "function_call", "call_id": "call_real", "name": "lookup", "arguments": "{}"},
			map[string]any{"type": "function_call_output", "call_id": "call_real", "output": "result"},
		}
		got := filterCodexInputWithOptions(input, codexInputFilterOptions{PreserveReferences: preserve})
		require.Len(t, got, 3)
		standalone := got[0].(map[string]any)
		require.NotContains(t, standalone, "call_id")
		require.Equal(t, "event", standalone["output"])
		require.Equal(t, "codex_app", standalone["namespace"])
		require.Equal(t, got[1].(map[string]any)["call_id"], got[2].(map[string]any)["call_id"])
		require.NotEmpty(t, got[1].(map[string]any)["call_id"])
	}
}

func TestForwardOAuthPreservesStandaloneOutputWithItemID(t *testing.T) {
	upstream := &httpUpstreamRecorder{resp: &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
		Body:       io.NopCloser(strings.NewReader("data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_test\",\"output\":[],\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}\n\n")),
	}}
	svc := newOpenAIImageGenerationControlTestService(upstream)
	c, _ := newOpenAIImageGenerationControlTestContext(true, "codex_cli_rs/0.167.0")
	account := newOpenAIImageGenerationControlTestAccount()
	account.Type = AccountTypeOAuth
	account.Credentials = map[string]any{"access_token": "test-token", "chatgpt_account_id": "test-account"}
	body := []byte(`{"model":"gpt-6.1-sol","instructions":"test","store":false,"stream":true,"input":[{"type":"function_call_output","id":"fco_test_event","name":"external_event","namespace":"codex_app","output":"WQ_EVENT_OK"}]}`)
	_, err := svc.Forward(context.Background(), c, account, body)
	require.NoError(t, err)
	item := gjson.GetBytes(upstream.lastBody, `input.#(name=="external_event")`)
	require.True(t, item.Exists(), "独立事件不能被当作孤立的配对结果删除")
	require.False(t, item.Get("call_id").Exists(), "不能把条目 id 当作 call_id")
	require.Equal(t, "codex_app", item.Get("namespace").String())
	require.Equal(t, "WQ_EVENT_OK", item.Get("output").String())
}

func TestNamespacedStandaloneOutputValidationParity(t *testing.T) {
	for _, id := range []string{"", `,"call_id":null`, `,"call_id":""`, `,"call_id":123`, `,"call_id":"call_real"`} {
		t.Run(id, func(t *testing.T) {
			body := []byte(`{"input":[{"type":"function_call_output","name":"external_event","namespace":"codex_app","output":"event"` + id + `}]}`)
			var decoded map[string]any
			require.NoError(t, json.Unmarshal(body, &decoded))
			fromBytes := ValidateFunctionCallOutputContextBytes(body)
			require.Equal(t, ValidateFunctionCallOutputContext(decoded), fromBytes)
			if id == "" || id == `,"call_id":null` {
				require.False(t, fromBytes.HasFunctionCallOutput, "独立事件不参与配对输出校验")
			} else {
				require.True(t, fromBytes.HasFunctionCallOutput)
			}
		})
	}
}

func TestStripOpenAIResponsesInputNamespacesPreservesStandaloneEvent(t *testing.T) {
	body := []byte(`{"input":[{"type":"function_call_output","name":"external_event","namespace":"codex_app","output":"event"},{"type":"function_call_output","call_id":"call_real","namespace":"legacy","output":"result"}]}`)
	got, err := stripOpenAIResponsesInputNamespaces(body, true)
	require.NoError(t, err)
	require.Equal(t, "codex_app", gjson.GetBytes(got, "input.0.namespace").String())
	require.Equal(t, "external_event", gjson.GetBytes(got, "input.0.name").String())
	require.Equal(t, "event", gjson.GetBytes(got, "input.0.output").String())
	require.False(t, gjson.GetBytes(got, "input.0.call_id").Exists())
	require.False(t, gjson.GetBytes(got, "input.1.namespace").Exists())
	// compact / 标准 API 等未启用命名空间的路径保持现有清理规则。
	stripped, err := stripOpenAIResponsesInputNamespaces(body, false)
	require.NoError(t, err)
	require.False(t, gjson.GetBytes(stripped, "input.0.namespace").Exists())
}
