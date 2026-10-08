package service

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

func TestNormalizeIntegralFloatLiterals(t *testing.T) {
	cases := []struct {
		name, in, want string
		changed        bool
	}{
		{"integral floats", `{"cell_id":"1","yield_time_ms":30000.0,"max_tokens":2000.00}`, `{"cell_id":"1","yield_time_ms":30000,"max_tokens":2000}`, true},
		{"negative and zero", `{"a":-2.0,"b":0.0,"c":-0.0}`, `{"a":-2,"b":0,"c":0}`, true},
		{"nested arrays", `{"ids":[1.0,2.5,3.0],"o":{"n":7.0}}`, `{"ids":[1,2.5,3],"o":{"n":7}}`, true},
		{"string content untouched", `{"chars":"print(1.0)\n\"2.0\"","n":5.0}`, `{"chars":"print(1.0)\n\"2.0\"","n":5}`, true},
		{"fraction and exponent kept", `{"a":1.5,"b":1.0e3,"c":2.05}`, `{"a":1.5,"b":1.0e3,"c":2.05}`, false},
		{"already integer", `{"session_id":74746}`, `{"session_id":74746}`, false},
		{"invalid json untouched", `{"a":1.0`, `{"a":1.0`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, changed := normalizeIntegralFloatLiterals(tc.in)
			require.Equal(t, tc.want, got)
			require.Equal(t, tc.changed, changed)
		})
	}
}

func TestNormalizeGrokFunctionCallArgumentsPayloadOnlyForGrok(t *testing.T) {
	payload := []byte(`{"type":"response.output_item.done","output_index":0,"item":{"type":"function_call","id":"fc_1","call_id":"call_1","name":"wait","arguments":"{\"cell_id\":\"1\",\"yield_time_ms\":30000.0}"}}`)

	got := normalizeGrokFunctionCallArgumentsPayload(&Account{Platform: PlatformGrok}, payload)
	require.Equal(t, `{"cell_id":"1","yield_time_ms":30000}`, gjson.GetBytes(got, "item.arguments").String())

	require.Equal(t, payload, normalizeGrokFunctionCallArgumentsPayload(&Account{Platform: PlatformOpenAI}, payload))
	require.Equal(t, payload, normalizeGrokFunctionCallArgumentsPayload(nil, payload))
}

func TestNormalizeGrokFunctionCallArgumentsPayloadCoversDoneAndTerminalEvents(t *testing.T) {
	grok := &Account{Platform: PlatformGrok}

	done := normalizeGrokFunctionCallArgumentsPayload(grok, []byte(`{"type":"response.function_call_arguments.done","item_id":"fc_1","arguments":"{\"session_id\":74746.0}"}`))
	require.Equal(t, `{"session_id":74746}`, gjson.GetBytes(done, "arguments").String())

	completed := normalizeGrokFunctionCallArgumentsPayload(grok, []byte(`{"type":"response.completed","response":{"output":[{"type":"message","content":[{"type":"output_text","text":"1.0"}]},{"type":"function_call","name":"write_stdin","arguments":"{\"session_id\":5.0}"}]}}`))
	require.Equal(t, "1.0", gjson.GetBytes(completed, "response.output.0.content.0.text").String())
	require.Equal(t, `{"session_id":5}`, gjson.GetBytes(completed, "response.output.1.arguments").String())

	nonStream := normalizeGrokFunctionCallArgumentsPayload(grok, []byte(`{"id":"resp_1","output":[{"type":"function_call","name":"wait","arguments":"{\"max_tokens\":2000.0}"}]}`))
	require.Equal(t, `{"max_tokens":2000}`, gjson.GetBytes(nonStream, "output.0.arguments").String())

	delta := []byte(`{"type":"response.function_call_arguments.delta","item_id":"fc_1","delta":"30000.0"}`)
	require.Equal(t, delta, normalizeGrokFunctionCallArgumentsPayload(grok, delta))
}

func grokIntegralArgsTestAccount() *Account {
	return &Account{
		ID:          5901,
		Name:        "grok-api-key",
		Platform:    PlatformGrok,
		Type:        AccountTypeAPIKey,
		Concurrency: 2,
		Credentials: map[string]any{"api_key": "xai-test-key", "base_url": "https://api.x.ai/v1"},
	}
}

func TestForwardGrokResponsesStreamingNormalizesIntegralFloatArguments(t *testing.T) {
	gin.SetMode(gin.TestMode)

	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	body := []byte(`{"model":"grok","input":"wait","stream":true,"tools":[{"type":"function","name":"wait","parameters":{"type":"object","properties":{"yield_time_ms":{"type":"number"}}}}]}`)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")

	item := `{"type":"function_call","id":"fc_wait","call_id":"call_wait","name":"wait","arguments":"{\"cell_id\":\"1\",\"yield_time_ms\":30000.0}","status":"completed"}`
	upstreamBody := strings.Join([]string{
		`data: {"type":"response.output_item.done","sequence_number":0,"output_index":0,"item":` + item + `}`,
		"",
		`data: {"type":"response.completed","sequence_number":1,"response":{"id":"resp_grok_wait","model":"grok-4.6","status":"completed","output":[` + item + `],"usage":{"input_tokens":2,"output_tokens":1}}}`,
		"",
	}, "\n")
	upstream := &httpUpstreamRecorder{resp: &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
		Body:       io.NopCloser(strings.NewReader(upstreamBody)),
	}}
	svc := &OpenAIGatewayService{httpUpstream: upstream}

	_, err := svc.forwardGrokResponses(context.Background(), c, grokIntegralArgsTestAccount(), body, "grok", true, time.Now())
	require.NoError(t, err)

	out := recorder.Body.String()
	require.NotContains(t, out, `30000.0`)
	require.Equal(t, 2, strings.Count(out, `{\"cell_id\":\"1\",\"yield_time_ms\":30000}`))
}

func TestForwardGrokResponsesNonStreamingNormalizesIntegralFloatArguments(t *testing.T) {
	gin.SetMode(gin.TestMode)

	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	body := []byte(`{"model":"grok","input":"wait","stream":false}`)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")

	upstream := &httpUpstreamRecorder{resp: &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body: io.NopCloser(strings.NewReader(`{"id":"resp_grok_wait","object":"response","model":"grok-4.6","status":"completed",
			"output":[{"type":"function_call","id":"fc_ws","call_id":"call_ws","name":"write_stdin","arguments":"{\"session_id\":74746.0,\"chars\":\"x\"}","status":"completed"}],
			"usage":{"input_tokens":2,"output_tokens":1}}`)),
	}}
	svc := &OpenAIGatewayService{httpUpstream: upstream}

	_, err := svc.forwardGrokResponses(context.Background(), c, grokIntegralArgsTestAccount(), body, "grok", false, time.Now())
	require.NoError(t, err)
	require.Equal(t, `{"session_id":74746,"chars":"x"}`, gjson.Get(recorder.Body.String(), "output.0.arguments").String())
}
