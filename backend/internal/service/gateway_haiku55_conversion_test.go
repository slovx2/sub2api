//go:build unit

package service

import (
	"bytes"
	"context"
	"encoding/json"
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

// Haiku 5.5 经四条转换路径（Responses / Chat Completions → Anthropic）时的思考映射：
// 上游只接受 adaptive + output_config.effort；与 Opus/Sonnet 5.5 不同，强制 tool_choice 可用。

// haiku55ConversionRequest 构造带 reasoning 档位的入站请求；forced 为 true 时附带
// 强制工具调用（tool_choice=required）。
func haiku55ConversionRequest(t *testing.T, chat bool, effort string, forced bool) []byte {
	t.Helper()
	parameters := map[string]any{"type": "object", "properties": map[string]any{}}
	request := map[string]any{"model": convertedCachePublicModel}
	if chat {
		request["messages"] = []map[string]any{{"role": "user", "content": "hello"}}
		request["reasoning_effort"] = effort
		if forced {
			request["tools"] = []map[string]any{{"type": "function", "function": map[string]any{"name": "lookup", "parameters": parameters}}}
		}
	} else {
		request["input"] = "hello"
		request["reasoning"] = map[string]any{"effort": effort}
		if forced {
			request["tools"] = []map[string]any{{"type": "function", "name": "lookup", "parameters": parameters}}
		}
	}
	if forced {
		request["tool_choice"] = "required"
	}
	body, err := json.Marshal(request)
	require.NoError(t, err)
	return body
}

type haiku55ConversionPath struct {
	name string
	// forward 把请求转发给映射到 claude-haiku-5-5 的账号，返回下游响应、发往上游的
	// 请求体（未到达上游时为 nil）以及转发错误。
	forward func(t *testing.T, effort string, forced bool) (*httptest.ResponseRecorder, []byte, error)
}

func haiku55ConversionPaths() []haiku55ConversionPath {
	const upstreamModel = "claude-haiku-5-5"
	anthropicPlatform := func(chat bool) func(*testing.T, string, bool) (*httptest.ResponseRecorder, []byte, error) {
		return func(t *testing.T, effort string, forced bool) (*httptest.ResponseRecorder, []byte, error) {
			body := haiku55ConversionRequest(t, chat, effort, forced)
			rec := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(rec)
			c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader(body))
			upstream := &anthropicHTTPUpstreamRecorder{resp: &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
				Body:       io.NopCloser(strings.NewReader(namespaceToolAnthropicStream())),
			}}
			svc := &GatewayService{cfg: &config.Config{}, httpUpstream: upstream}
			account := convertedCacheAnthropicAPIKeyAccount(upstreamModel)
			var err error
			if chat {
				_, err = svc.ForwardAsChatCompletions(context.Background(), c, account, body, nil)
			} else {
				_, err = svc.ForwardAsResponses(context.Background(), c, account, body, nil)
			}
			return rec, upstream.lastBody, err
		}
	}
	nativeAnthropic := func(chat bool) func(*testing.T, string, bool) (*httptest.ResponseRecorder, []byte, error) {
		return func(t *testing.T, effort string, forced bool) (*httptest.ResponseRecorder, []byte, error) {
			body := haiku55ConversionRequest(t, chat, effort, forced)
			rec := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(rec)
			upstream := &httpUpstreamRecorder{resp: nativeAnthropicStreamResponse()}
			svc := &OpenAIGatewayService{cfg: rawChatCompletionsTestConfig(), httpUpstream: upstream}
			account := convertedCacheCommandCodeAccount(upstreamModel)
			var err error
			if chat {
				c.Request = httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
				_, err = svc.ForwardAsChatCompletions(context.Background(), c, account, body, "", "")
			} else {
				c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader(body))
				_, err = svc.Forward(context.Background(), c, account, body)
			}
			return rec, upstream.lastBody, err
		}
	}
	return []haiku55ConversionPath{
		{"anthropic_responses", anthropicPlatform(false)},
		{"anthropic_chat_completions", anthropicPlatform(true)},
		{"native_responses", nativeAnthropic(false)},
		{"native_chat_completions", nativeAnthropic(true)},
	}
}

func TestHaiku55ConversionUsesAdaptiveThinking(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, path := range haiku55ConversionPaths() {
		for _, effort := range []string{"low", "medium", "high"} {
			for _, forced := range []bool{false, true} {
				name := path.name + "/" + effort
				if forced {
					name += "/forced_tool_choice"
				}
				t.Run(name, func(t *testing.T) {
					_, upstreamBody, err := path.forward(t, effort, forced)

					require.NoError(t, err)
					require.NotNil(t, upstreamBody)
					require.Equal(t, "claude-haiku-5-5", gjson.GetBytes(upstreamBody, "model").String())
					require.Equal(t, "adaptive", gjson.GetBytes(upstreamBody, "thinking.type").String())
					require.False(t, gjson.GetBytes(upstreamBody, "thinking.budget_tokens").Exists())
					require.Equal(t, effort, gjson.GetBytes(upstreamBody, "output_config.effort").String())
					if forced {
						require.Equal(t, "any", gjson.GetBytes(upstreamBody, "tool_choice.type").String())
					} else {
						require.False(t, gjson.GetBytes(upstreamBody, "tool_choice").Exists())
					}
				})
			}
		}
	}
}

// 目录之外的档位在本地以 400 拒绝，不发往上游。none 不在此列：Responses 入口会先把它
// 当作「未指定」剥掉（filterOpenAIResponsesNoneReasoningEffortForAccount），各路径表现不一。
func TestHaiku55ConversionRejectsUnsupportedEffort(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, path := range haiku55ConversionPaths() {
		for _, effort := range []string{"xhigh", "max"} {
			t.Run(path.name+"/"+effort, func(t *testing.T) {
				rec, upstreamBody, err := path.forward(t, effort, false)

				require.ErrorContains(t, err, "does not support reasoning effort")
				require.Nil(t, upstreamBody)
				require.Equal(t, http.StatusBadRequest, rec.Code)
				require.Contains(t, rec.Body.String(), "use low, medium, high")
			})
		}
	}
}
