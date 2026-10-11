//go:build unit

package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

// 协议转换（Responses / Chat Completions → Anthropic Messages）产出的请求体上的 cache
// 断点。四条转换路径共用 addConvertedClaudeCacheBreakpoints，这里从真实入口截获发往
// 上游的请求体做断言。

const convertedCachePublicModel = "public-model"

// convertedCacheRequest 构造带 system、两个工具、五条消息的入站请求：足够触发全部
// 四个断点（tools 末项、system 末块、末条消息、倒数第二条 user 消息）。
func convertedCacheRequest(t *testing.T, chat bool, model string) []byte {
	t.Helper()
	turns := []map[string]any{
		{"role": "user", "content": "first question"},
		{"role": "assistant", "content": "first answer"},
		{"role": "user", "content": "second question"},
		{"role": "assistant", "content": "second answer"},
		{"role": "user", "content": "third question"},
	}
	parameters := map[string]any{"type": "object", "properties": map[string]any{"q": map[string]any{"type": "string"}}}
	request := map[string]any{"model": model}
	if chat {
		request["messages"] = append([]map[string]any{{"role": "system", "content": "You are a careful assistant."}}, turns...)
		request["tools"] = []map[string]any{
			{"type": "function", "function": map[string]any{"name": "lookup", "description": "Look things up", "parameters": parameters}},
			{"type": "function", "function": map[string]any{"name": "save", "description": "Save a note", "parameters": parameters}},
		}
	} else {
		request["instructions"] = "You are a careful assistant."
		request["input"] = turns
		request["tools"] = []map[string]any{
			{"type": "function", "name": "lookup", "description": "Look things up", "parameters": parameters},
			{"type": "function", "name": "save", "description": "Save a note", "parameters": parameters},
		}
	}
	body, err := json.Marshal(request)
	require.NoError(t, err)
	return body
}

// convertedCacheControlPaths 按 tools → system → messages 的渲染顺序列出全部断点路径。
func convertedCacheControlPaths(body []byte) []string {
	_, messagePaths, toolPaths, systemPaths := collectCacheControlPaths(body)
	paths := append([]string{}, toolPaths...)
	paths = append(paths, systemPaths...)
	return append(paths, messagePaths...)
}

func convertedCacheAnthropicAPIKeyAccount(upstreamModel string) *Account {
	return &Account{
		ID: 1, Platform: PlatformAnthropic, Type: AccountTypeAPIKey,
		Credentials: map[string]any{
			"api_key":       "fixture-key",
			"model_mapping": map[string]any{convertedCachePublicModel: upstreamModel},
		},
	}
}

// convertedCacheCommandCodeAccount 用独立的示例地址，并把模型目录标成不可用：不触发
// 目录拉取，按内置规则分流（claude-* → Anthropic Messages）。
func convertedCacheCommandCodeAccount(upstreamModel string) *Account {
	base := fmt.Sprintf("http://cc-cache-%d.example", time.Now().UnixNano())
	account := commandCodeTestAccount(31)
	account.Credentials["api_base_urls"] = map[string]any{
		APIProtocolChatCompletions: base + "/provider/v1",
		APIProtocolResponses:       base + "/provider/v1",
		APIProtocolAnthropic:       base + "/provider",
	}
	account.Credentials["model_mapping"] = map[string]any{convertedCachePublicModel: upstreamModel}
	url := buildOpenAIModelsURL(base + "/provider/v1")
	upstreamModelProtocols.store(modelProtocolCatalogKey(account, url), nil, errors.New("unavailable"), time.Now())
	return account
}

// forwardConvertedViaAnthropicPlatform 走 Anthropic 平台账号的转换路径
// （ForwardAsResponses / ForwardAsChatCompletions），返回发往上游的请求体。
func forwardConvertedViaAnthropicPlatform(t *testing.T, chat bool, account *Account, model string) []byte {
	t.Helper()
	body := convertedCacheRequest(t, chat, model)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader(body))
	upstream := &anthropicHTTPUpstreamRecorder{resp: &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
		Body:       io.NopCloser(strings.NewReader(namespaceToolAnthropicStream())),
	}}
	svc := &GatewayService{cfg: &config.Config{}, httpUpstream: upstream}
	var err error
	if chat {
		_, err = svc.ForwardAsChatCompletions(context.Background(), c, account, body, nil)
	} else {
		_, err = svc.ForwardAsResponses(context.Background(), c, account, body, nil)
	}
	require.NoError(t, err)
	require.NotNil(t, upstream.lastReq)
	return upstream.lastBody
}

// forwardConvertedViaNativeAnthropic 走 OpenAI 网关的原生 Anthropic 端点转换路径
// （forwardResponsesViaNativeAnthropic / forwardChatCompletionsViaNativeAnthropic）。
func forwardConvertedViaNativeAnthropic(t *testing.T, chat bool, account *Account, model string) []byte {
	t.Helper()
	body := convertedCacheRequest(t, chat, model)
	upstream := &httpUpstreamRecorder{err: errors.New("stop after capture")}
	svc := &OpenAIGatewayService{cfg: rawChatCompletionsTestConfig(), httpUpstream: upstream}
	var err error
	if chat {
		_, err = svc.ForwardAsChatCompletions(context.Background(), adaptiveProtocolTestContext("/v1/chat/completions", body), account, body, "", "")
	} else {
		_, err = svc.Forward(context.Background(), adaptiveProtocolTestContext("/v1/responses", body), account, body)
	}
	require.Error(t, err)
	require.NotNil(t, upstream.lastReq)
	require.True(t, strings.HasSuffix(upstream.lastReq.URL.Path, "/v1/messages"), upstream.lastReq.URL.Path)
	return upstream.lastBody
}

type convertedCachePath struct {
	name string
	// forward 把公开模型名映射到 upstreamModel 后转发，返回发往上游的 Anthropic 请求体。
	forward func(t *testing.T, upstreamModel string) []byte
}

func convertedCachePaths() []convertedCachePath {
	return []convertedCachePath{
		{"anthropic_responses", func(t *testing.T, upstreamModel string) []byte {
			return forwardConvertedViaAnthropicPlatform(t, false, convertedCacheAnthropicAPIKeyAccount(upstreamModel), convertedCachePublicModel)
		}},
		{"anthropic_chat_completions", func(t *testing.T, upstreamModel string) []byte {
			return forwardConvertedViaAnthropicPlatform(t, true, convertedCacheAnthropicAPIKeyAccount(upstreamModel), convertedCachePublicModel)
		}},
		{"native_responses", func(t *testing.T, upstreamModel string) []byte {
			return forwardConvertedViaNativeAnthropic(t, false, convertedCacheCommandCodeAccount(upstreamModel), convertedCachePublicModel)
		}},
		{"native_chat_completions", func(t *testing.T, upstreamModel string) []byte {
			return forwardConvertedViaNativeAnthropic(t, true, convertedCacheCommandCodeAccount(upstreamModel), convertedCachePublicModel)
		}},
	}
}

func TestConvertedClaudeRequestsCarryCacheBreakpoints(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, path := range convertedCachePaths() {
		for _, upstreamModel := range []string{"claude-sonnet-5-5", "claude-haiku-5-5"} {
			t.Run(path.name+"/"+upstreamModel, func(t *testing.T) {
				body := path.forward(t, upstreamModel)

				require.Equal(t, upstreamModel, gjson.GetBytes(body, "model").String())
				paths := convertedCacheControlPaths(body)
				require.Equal(t, []string{
					"tools.1.cache_control",
					"system.0.cache_control",
					"messages.2.content.0.cache_control",
					"messages.4.content.0.cache_control",
				}, paths)
				require.LessOrEqual(t, len(paths), maxCacheControlBlocks)
				for _, p := range paths {
					require.JSONEq(t, `{"type":"ephemeral","ttl":"5m"}`, gjson.GetBytes(body, p).Raw, p)
				}
				// 打断点不改变内容本身。
				require.Equal(t, "You are a careful assistant.", gjson.GetBytes(body, "system.0.text").String())
				require.Equal(t, "second question", gjson.GetBytes(body, "messages.2.content.0.text").String())
				require.Equal(t, "third question", gjson.GetBytes(body, "messages.4.content.0.text").String())
				require.Equal(t, "save", gjson.GetBytes(body, "tools.1.name").String())
			})
		}
	}
}

// 非 Claude 上游（映射后的模型名判断）不注入任何断点：这些 Anthropic 兼容端点是否
// 接受 cache_control 没有验证过。
func TestConvertedNonClaudeRequestsStayUnmarked(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tests := []struct {
		name          string
		upstreamModel string
		forward       func(t *testing.T) []byte
	}{
		{"anthropic_responses", "deepseek-v4-pro", func(t *testing.T) []byte {
			return forwardConvertedViaAnthropicPlatform(t, false, convertedCacheAnthropicAPIKeyAccount("deepseek-v4-pro"), convertedCachePublicModel)
		}},
		{"anthropic_chat_completions", "glm-5.3", func(t *testing.T) []byte {
			return forwardConvertedViaAnthropicPlatform(t, true, convertedCacheAnthropicAPIKeyAccount("glm-5.3"), convertedCachePublicModel)
		}},
		{"native_responses", "k3", func(t *testing.T) []byte {
			return forwardConvertedViaNativeAnthropic(t, false, nativeAnthropicTestAccount(), "k3")
		}},
		{"native_chat_completions", "k3", func(t *testing.T) []byte {
			return forwardConvertedViaNativeAnthropic(t, true, nativeAnthropicTestAccount(), "k3")
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := tt.forward(t)

			require.Equal(t, tt.upstreamModel, gjson.GetBytes(body, "model").String())
			require.Empty(t, convertedCacheControlPaths(body))
			require.NotContains(t, string(body), "cache_control")
			// system 与消息内容保持转换器产出的原始形态（未被升级成块数组）。
			require.Equal(t, gjson.String, gjson.GetBytes(body, "system").Type)
			require.Equal(t, gjson.String, gjson.GetBytes(body, "messages.4.content").Type)
		})
	}
}

// OAuth 账号的断点由 Claude Code 伪装链路负责：转换路径不能再叠加一套。伪装链路
// 默认只打 system 与 tools 末项，messages 断点受系统设置控制（此处未开启）。
func TestConvertedOAuthRequestsKeepMimicryBreakpoints(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, chat := range []bool{false, true} {
		name := "responses"
		if chat {
			name = "chat_completions"
		}
		t.Run(name, func(t *testing.T) {
			account := &Account{
				ID: 2, Platform: PlatformAnthropic, Type: AccountTypeOAuth,
				Credentials: map[string]any{"access_token": "fixture-token"},
			}
			body := forwardConvertedViaAnthropicPlatform(t, chat, account, "claude-sonnet-5-5")

			_, messagePaths, toolPaths, systemPaths := collectCacheControlPaths(body)
			require.Empty(t, messagePaths, "转换路径不应在伪装链路之外再打 messages 断点")
			require.Equal(t, []string{"tools.1.cache_control"}, toolPaths)
			require.Len(t, systemPaths, 1)

			// 与单独执行伪装链路的结果逐字节一致：断点全部来自伪装链路。
			converted := convertedAnthropicBodyForOAuthTest(t, chat, "claude-sonnet-5-5")
			svc := &GatewayService{cfg: &config.Config{}}
			want := enforceCacheControlLimit(svc.applyClaudeCodeOAuthMimicryToBody(
				context.Background(), nil, account, converted, gjson.GetBytes(converted, "system").Value(), "claude-sonnet-5-5",
			))
			require.Equal(t, convertedCacheControlPaths(want), convertedCacheControlPaths(body))
		})
	}
}

// convertedAnthropicBodyForOAuthTest 复现转换路径在伪装之前的请求体。
func convertedAnthropicBodyForOAuthTest(t *testing.T, chat bool, model string) []byte {
	t.Helper()
	body := forwardConvertedViaAnthropicPlatform(t, chat, convertedCacheAnthropicAPIKeyAccount("deepseek-v4-pro"), convertedCachePublicModel)
	out, ok := setJSONValueBytes(body, "model", model)
	require.True(t, ok)
	return out
}

func TestAddConvertedClaudeCacheBreakpoints(t *testing.T) {
	const marker = `{"type":"ephemeral","ttl":"5m"}`
	tests := []struct {
		name  string
		model string
		body  string
		// want 为 nil 表示请求体必须逐字节不变。
		want map[string]string
	}{
		{
			name:  "string_system_and_content_are_promoted",
			model: "claude-sonnet-5-5",
			body:  `{"system":"sys","tools":[{"name":"a"},{"name":"b"}],"messages":[{"role":"user","content":"hi"}]}`,
			want: map[string]string{
				"tools.1.cache_control":              marker,
				"system.0.cache_control":             marker,
				"messages.0.content.0.cache_control": marker,
			},
		},
		{
			name:  "second_to_last_user_needs_four_messages",
			model: "claude-haiku-5-5",
			body:  `{"messages":[{"role":"user","content":"1"},{"role":"assistant","content":"2"},{"role":"user","content":[{"type":"tool_result","tool_use_id":"t","content":"3"}]}]}`,
			want:  map[string]string{"messages.2.content.0.cache_control": marker},
		},
		{
			name:  "last_block_of_multi_block_content",
			model: "anthropic/claude-sonnet-5.5",
			body:  `{"system":[{"type":"text","text":"a"},{"type":"text","text":"b"}],"messages":[{"role":"user","content":[{"type":"text","text":"x"},{"type":"text","text":"y"}]}]}`,
			want: map[string]string{
				"system.1.cache_control":             marker,
				"messages.0.content.1.cache_control": marker,
			},
		},
		{
			name:  "existing_ttl_is_kept_and_missing_ttl_is_filled",
			model: "claude-opus-4-5@20251101",
			body:  `{"system":[{"type":"text","text":"a","cache_control":{"type":"ephemeral","ttl":"1h"}}],"tools":[{"name":"a","cache_control":{"type":"ephemeral"}}],"messages":[{"role":"user","content":"hi"}]}`,
			want: map[string]string{
				"tools.0.cache_control":              marker,
				"system.0.cache_control":             `{"type":"ephemeral","ttl":"1h"}`,
				"messages.0.content.0.cache_control": marker,
			},
		},
		{
			name:  "deferred_tools_are_skipped",
			model: "claude-sonnet-5-5",
			body:  `{"tools":[{"name":"a"},{"name":"b","defer_loading":true}],"messages":[{"role":"user","content":"hi"}]}`,
			want: map[string]string{
				"tools.0.cache_control":              marker,
				"messages.0.content.0.cache_control": marker,
			},
		},
		{
			name:  "blank_system_is_left_alone",
			model: "claude-sonnet-5-5",
			body:  `{"system":"  ","messages":[{"role":"user","content":"hi"}]}`,
			want:  map[string]string{"messages.0.content.0.cache_control": marker},
		},
		{name: "deepseek", model: "deepseek-v4-pro", body: `{"system":"sys","tools":[{"name":"a"}],"messages":[{"role":"user","content":"hi"}]}`},
		{name: "kimi", model: "kimi-k3", body: `{"system":"sys","tools":[{"name":"a"}],"messages":[{"role":"user","content":"hi"}]}`},
		{name: "glm_with_vendor_prefix", model: "zai-org/glm-5.3", body: `{"system":"sys","tools":[{"name":"a"}],"messages":[{"role":"user","content":"hi"}]}`},
		{name: "gpt", model: "gpt-5.5", body: `{"system":"sys","tools":[{"name":"a"}],"messages":[{"role":"user","content":"hi"}]}`},
		{name: "empty_model", model: "", body: `{"system":"sys","tools":[{"name":"a"}],"messages":[{"role":"user","content":"hi"}]}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := addConvertedClaudeCacheBreakpoints([]byte(tt.body), tt.model)
			if tt.want == nil {
				require.Equal(t, tt.body, string(out))
				return
			}
			require.True(t, json.Valid(out))
			paths := convertedCacheControlPaths(out)
			require.Len(t, paths, len(tt.want))
			for path, want := range tt.want {
				require.JSONEq(t, want, gjson.GetBytes(out, path).Raw, path)
			}
			// 再跑一遍结果不变；过完上限裁剪后总数不超过 4。
			require.JSONEq(t, string(out), string(addConvertedClaudeCacheBreakpoints(out, tt.model)))
			require.LessOrEqual(t, len(convertedCacheControlPaths(enforceCacheControlLimit(out))), maxCacheControlBlocks)
		})
	}
}
