package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

func TestNormalizeDeepSeekResponsesWebSearchCalls(t *testing.T) {
	cases := []struct {
		name        string
		items       string
		wantChanged bool
		check       func(t *testing.T, input gjson.Result)
	}{
		{
			name:        "search 只有 query 时补 queries",
			items:       `{"type":"web_search_call","id":"ws_1","status":"completed","action":{"type":"search","query":"night light"}}`,
			wantChanged: true,
			check: func(t *testing.T, input gjson.Result) {
				require.Len(t, input.Array(), 3)
				require.Equal(t, `["night light"]`, input.Get("1.action.queries").Raw)
				require.Equal(t, "night light", input.Get("1.action.query").String())
				require.Equal(t, "ws_1", input.Get("1.id").String())
			},
		},
		{
			name:        "search 没有 query 时补空 queries",
			items:       `{"type":"web_search_call","status":"completed","action":{"type":"search"}}`,
			wantChanged: true,
			check: func(t *testing.T, input gjson.Result) {
				require.Equal(t, `[]`, input.Get("1.action.queries").Raw)
			},
		},
		{
			name:        "缺 action 与缺 url 的条目被移除",
			items:       `{"type":"web_search_call","status":"completed"},{"type":"web_search_call","status":"completed","action":{"type":"open_page"}}`,
			wantChanged: true,
			check: func(t *testing.T, input gjson.Result) {
				require.Len(t, input.Array(), 2)
				require.Equal(t, "message", input.Get("1.type").String())
			},
		},
		{
			name: "合法形态保持不变",
			items: `{"type":"web_search_call","status":"completed","action":{"type":"search","queries":["a"]}},` +
				`{"type":"web_search_call","status":"completed","action":{"type":"open_page","url":"https://example.com"}},` +
				`{"type":"web_search_call","status":"completed","action":{"type":"find_in_page","url":"https://example.com","pattern":"x"}}`,
			wantChanged: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := []byte(`{"model":"deepseek-flash","input":[` +
				`{"type":"message","role":"user","content":"hi"},` + tc.items +
				`,{"type":"message","role":"user","content":"again"}]}`)
			rewritten, changed := normalizeDeepSeekResponsesWebSearchCalls(body)
			require.Equal(t, tc.wantChanged, changed)
			if !tc.wantChanged {
				require.Equal(t, body, rewritten)
				return
			}
			tc.check(t, gjson.GetBytes(rewritten, "input"))
		})
	}
}

func TestNormalizeDeepSeekResponsesWebSearchCallsSkipsWithoutWebSearch(t *testing.T) {
	body := []byte(`{"model":"deepseek-flash","input":[{"type":"message","role":"user","content":"hi"}]}`)
	rewritten, changed := normalizeDeepSeekResponsesWebSearchCalls(body)
	require.False(t, changed)
	require.Equal(t, body, rewritten)
}

// TestForwardDeepSeekResponsesRepairsWebSearchCalls 覆盖真实转发链路：从 xAI 等上游切到
// DeepSeek 的会话，历史里 web_search_call 只有 query，DeepSeek 会以 422
// "missing field `queries`" 拒绝整轮；网关必须在上游收到请求前补齐。
func TestForwardDeepSeekResponsesRepairsWebSearchCalls(t *testing.T) {
	body := []byte(`{"model":"deepseek-flash","stream":false,"input":[` +
		`{"type":"message","role":"user","content":"go"},` +
		`{"type":"web_search_call","id":"ws_1","status":"completed","action":{"type":"search","query":"night light"}},` +
		`{"type":"message","role":"user","content":"continue"}]}`)

	upstream := deepSeekResponsesTestUpstream()
	svc := &OpenAIGatewayService{httpUpstream: upstream}
	c := deepSeekResponsesTestContext(t, body)

	_, err := svc.Forward(context.Background(), c, deepSeekResponsesTestAccount(), body)
	require.NoError(t, err)
	require.Equal(t, "https://api.deepseek.com/responses", upstream.lastReq.URL.String())
	require.Equal(t, `["night light"]`, gjson.GetBytes(upstream.lastBody, "input.1.action.queries").Raw)
}
