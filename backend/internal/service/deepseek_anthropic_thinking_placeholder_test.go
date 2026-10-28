//go:build unit

package service

import (
	"context"
	"strconv"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

// deepSeekChainedToolUseBody 复刻线上 400 的形态：同一轮里第一次工具调用带
// thinking，后续链式工具调用的 assistant 消息模型没吐 thinking。
const deepSeekChainedToolUseBody = `{"model":"deepseek-v4.1-flash","max_tokens":64,"stream":false,` +
	`"thinking":{"type":"enabled","budget_tokens":1024},"messages":[` +
	`{"role":"user","content":"整理目录"},` +
	`{"role":"assistant","content":[{"type":"thinking","thinking":"先列目录","signature":""},` +
	`{"type":"tool_use","id":"call_1","name":"Bash","input":{"command":"ls"}}]},` +
	`{"role":"user","content":[{"type":"tool_result","tool_use_id":"call_1","content":"a b"}]},` +
	`{"role":"assistant","content":[{"type":"text","text":"再看 a"},` +
	`{"type":"tool_use","id":"call_2","name":"Bash","input":{"command":"cat a"}}]},` +
	`{"role":"user","content":[{"type":"tool_result","tool_use_id":"call_2","content":"x"}]},` +
	`{"role":"assistant","content":[{"type":"text","text":"完成"}]},` +
	`{"role":"user","content":"继续"}]}`

func contentTypesOf(t *testing.T, body []byte, index int) []string {
	t.Helper()
	var types []string
	for _, block := range gjson.GetBytes(body, "messages."+strconv.Itoa(index)+".content").Array() {
		types = append(types, block.Get("type").String())
	}
	return types
}

func TestEnsureDeepSeekAnthropicThinkingPlaceholders_FillsToolUseMessages(t *testing.T) {
	out := EnsureDeepSeekAnthropicThinkingPlaceholders([]byte(deepSeekChainedToolUseBody), "deepseek-v4.1-flash")

	require.True(t, gjson.ValidBytes(out))
	// 已有 thinking 的消息保持不变。
	require.Equal(t, []string{"thinking", "tool_use"}, contentTypesOf(t, out, 1))
	require.Equal(t, "先列目录", gjson.GetBytes(out, "messages.1.content.0.thinking").String())
	// 缺 thinking 的 tool_use 消息在开头补占位。
	require.Equal(t, []string{"thinking", "text", "tool_use"}, contentTypesOf(t, out, 3))
	require.Equal(t, " ", gjson.GetBytes(out, "messages.3.content.0.thinking").String())
	require.True(t, gjson.GetBytes(out, "messages.3.content.0.signature").Exists())
	// 纯文本 assistant 不动。
	require.Equal(t, []string{"text"}, contentTypesOf(t, out, 5))
	// 消息其余部分逐字节保留。
	require.Equal(t, gjson.Get(deepSeekChainedToolUseBody, "messages.3.content.1").Raw,
		gjson.GetBytes(out, "messages.3.content.2").Raw)
}

func TestEnsureDeepSeekAnthropicThinkingPlaceholders_Idempotent(t *testing.T) {
	once := EnsureDeepSeekAnthropicThinkingPlaceholders([]byte(deepSeekChainedToolUseBody), "deepseek-flash")
	twice := EnsureDeepSeekAnthropicThinkingPlaceholders(once, "deepseek-flash")
	require.Equal(t, string(once), string(twice))
}

func TestEnsureDeepSeekAnthropicThinkingPlaceholders_LeavesBodyUntouched(t *testing.T) {
	tests := []struct {
		name  string
		body  string
		model string
	}{
		{name: "non deepseek upstream", body: deepSeekChainedToolUseBody, model: "kimi-k3"},
		{name: "claude upstream", body: deepSeekChainedToolUseBody, model: "claude-sonnet-5-5"},
		{
			name:  "thinking disabled",
			body:  `{"model":"deepseek-flash","thinking":{"type":"disabled"},"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"c","name":"B","input":{}}]}]}`,
			model: "deepseek-flash",
		},
		{
			name:  "redacted thinking present",
			body:  `{"model":"deepseek-flash","messages":[{"role":"assistant","content":[{"type":"redacted_thinking","data":"x"},{"type":"tool_use","id":"c","name":"B","input":{}}]}]}`,
			model: "deepseek-flash",
		},
		{
			name:  "no tool use",
			body:  `{"model":"deepseek-flash","messages":[{"role":"user","content":"hi"},{"role":"assistant","content":[{"type":"text","text":"prefill"}]}]}`,
			model: "deepseek-flash",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := EnsureDeepSeekAnthropicThinkingPlaceholders([]byte(tt.body), tt.model)
			require.Equal(t, tt.body, string(out))
		})
	}
}

func TestNativeAnthropicPassthroughFillsDeepSeekThinkingPlaceholders(t *testing.T) {
	gin.SetMode(gin.TestMode)
	account := nativeAnthropicTestAccount()
	account.Name = "deepseek-native"
	account.Platform = PlatformDeepseek
	body := []byte(deepSeekChainedToolUseBody)
	upstream := &httpUpstreamRecorder{resp: nativeAnthropicBufferedResponse()}
	svc := &OpenAIGatewayService{cfg: rawChatCompletionsTestConfig(), httpUpstream: upstream}

	_, err := svc.ForwardAsAnthropic(context.Background(),
		adaptiveProtocolTestContext("/v1/messages", body), account, body, "", "")
	require.NoError(t, err)
	require.Equal(t, []string{"thinking", "text", "tool_use"}, contentTypesOf(t, upstream.lastBody, 3))
	require.Equal(t, " ", gjson.GetBytes(upstream.lastBody, "messages.3.content.0.thinking").String())
}
