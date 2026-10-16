package devin

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

func modelConfig(uid, label string, contextLength uint64, multimodal bool) []byte {
	var flag uint64
	if multimodal {
		flag = 1
	}
	inner := bytes.Join([][]byte{field(1, label), number(5, flag), number(10, 2), number(18, contextLength), field(22, uid)}, nil)
	return field(1, string(inner))
}

func TestParseCliModelConfigsAggregatesEffortVariants(t *testing.T) {
	body := bytes.Join([][]byte{
		modelConfig("gpt-6-1-sol-low", "GPT-6.1 Sol Low Thinking", 1000000, true),
		modelConfig("gpt-6-1-sol-high-priority", "GPT-6.1 Sol High Thinking Fast", 1000000, true),
		modelConfig("gpt-6-1-sol-max", "GPT-6.1 Sol Max Thinking", 1000000, true),
		modelConfig("gpt-6-1-sol-medium", "GPT-6.1 Sol Medium Thinking", 1000000, true),
		modelConfig("swe-1-6-fast", "SWE-1.6 Fast", 200000, false),
		modelConfig("claude-opus-4-6-thinking-1m", "Claude Opus 4.6 Thinking 1M", 1000000, true),
		modelConfig("MODEL_GPT_5_2_HIGH", "GPT-5.2 High", 400000, true),
	}, nil)

	models, err := ParseCliModelConfigs(body)
	require.NoError(t, err)
	require.Equal(t, []LiveModel{
		{ID: "gpt-6-1-sol", DisplayName: "GPT-6.1 Sol", ContextLength: 1000000, Multimodal: true, Levels: []string{"low", "medium", "high", "max"}},
		{ID: "swe-1-6", DisplayName: "SWE-1.6", ContextLength: 200000},
		{ID: "claude-opus-4-6-1m", DisplayName: "Claude Opus 4.6 Thinking 1M", ContextLength: 1000000, Multimodal: true},
		{ID: "MODEL_GPT_5_2", DisplayName: "GPT-5.2", ContextLength: 400000, Multimodal: true, Levels: []string{"high"}},
	}, models)

	catalog, err := LiveModelsCatalogJSON(models)
	require.NoError(t, err)
	sol := gjson.GetBytes(catalog, `data.#(id=="gpt-6-1-sol")`)
	require.True(t, sol.Get("reasoning").Bool())
	require.Equal(t, `["low","medium","high","max"]`, sol.Get("supported_reasoning_levels").Raw)
	require.Equal(t, int64(1000000), sol.Get("context_window").Int())
	require.Equal(t, `["text","image"]`, sol.Get("input_modalities").Raw)
	swe := gjson.GetBytes(catalog, `data.#(id=="swe-1-6")`)
	require.False(t, swe.Get("reasoning").Bool())
	require.False(t, swe.Get("supported_reasoning_levels").Exists())
}

func TestNewCliModelConfigsRequestIsReadOnlyUnary(t *testing.T) {
	req, err := NewCliModelConfigsRequest(context.Background(), DevinDefaultBaseURL+"/", "test")
	require.NoError(t, err)
	require.Equal(t, DevinDefaultBaseURL+DevinCliModelConfigsPath, req.URL.String())
	require.Equal(t, "application/proto", req.Header.Get("Content-Type"))
	require.Equal(t, "Basic test-test", req.Header.Get("Authorization"))
	body, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	require.Len(t, byteFields(t, body, 1), 1)
}

func TestResolveModelUIDPrefersAccountLevels(t *testing.T) {
	// 内置目录已收录 gpt-6-1-sol：点号写法也要带上档位后缀。
	require.Equal(t, "gpt-6-1-sol-high", ResolveDevinChatModelUID("gpt-6.1-sol", "high", 0, nil))
	require.Equal(t, "gpt-6-1-sol-medium", ResolveDevinChatModelUID("gpt-6.1-sol", "none", 0, nil), "不支持的 none 回到默认档")

	// 目录之外的新模型依赖账号同步到的档位。
	levels := func(model string) []string {
		if model == "gpt-6-2-sol" {
			return []string{"low", "medium", "high", "xhigh"}
		}
		return nil
	}
	require.Equal(t, "gpt-6-2-sol", ResolveDevinChatModelUID("gpt-6.2-sol", "max", 0, nil))
	require.Equal(t, "gpt-6-2-sol-xhigh", ResolveDevinChatModelUID("gpt-6.2-sol", "max", 0, levels))
	require.Equal(t, "gpt-6-2-sol-medium", ResolveDevinChatModelUID("gpt-6.2-sol", "", 0, levels))
	require.Equal(t, "gpt-6-astra-high", ResolveDevinChatModelUID("gpt-6-astra", "high", 0, levels))
}
