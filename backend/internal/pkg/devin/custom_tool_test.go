package devin

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/pkg/apicompat"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
	"google.golang.org/protobuf/encoding/protowire"
)

func varintField(t *testing.T, payload []byte, tag protowire.Number) (uint64, bool) {
	t.Helper()
	for len(payload) > 0 {
		n, typ, size := protowire.ConsumeTag(payload)
		require.Positive(t, size)
		payload = payload[size:]
		if typ == protowire.VarintType {
			v, size := protowire.ConsumeVarint(payload)
			require.Positive(t, size)
			if n == tag {
				return v, true
			}
			payload = payload[size:]
			continue
		}
		size = protowire.ConsumeFieldValue(n, typ, payload)
		require.Positive(t, size)
		payload = payload[size:]
	}
	return 0, false
}

func TestNativeRequestDeclaresCustomToolsAndReplaysCustomCalls(t *testing.T) {
	input := "await tools.exec_command({cmd: \"echo 'a\\\"b'\"})\n"
	arguments, _ := json.Marshal(map[string]string{"input": input})
	body, _ := json.Marshal(map[string]any{
		"model": "gpt-6-astra",
		"messages": []any{
			map[string]any{"role": "user", "content": "run"},
			map[string]any{"role": "assistant", "tool_calls": []any{map[string]any{"id": "call_exec", "type": "function", "function": map[string]any{"name": "exec", "arguments": string(arguments)}}}},
			map[string]any{"role": "tool", "tool_call_id": "call_exec", "content": "ok"},
		},
		"tools": []any{
			map[string]any{"type": "function", "function": map[string]any{"name": "exec", "description": "Run JavaScript", "parameters": json.RawMessage(`{"type":"object","properties":{"input":{"type":"string"}}}`)}},
			map[string]any{"type": "function", "function": map[string]any{"name": "wait", "description": "Wait", "parameters": json.RawMessage(`{"type":"object"}`)}},
			map[string]any{"type": "function", "function": map[string]any{"name": "note", "description": "Free text"}},
		},
	})
	opts := RequestOptions{CustomTools: map[string]json.RawMessage{
		"exec": json.RawMessage(`{"type":"grammar","syntax":"lark","definition":"start: /[\\s\\S]+/"}`),
		"note": json.RawMessage(`{"type":"text"}`),
	}}
	req, err := NewChatRequest(context.Background(), DevinDefaultBaseURL, "test", "session", body, opts)
	require.NoError(t, err)
	_, payload, err := ReadConnectFrame(req.Body)
	require.NoError(t, err)

	tools := byteFields(t, payload, 10)
	require.Len(t, tools, 3)
	exec, wait, note := tools[0], tools[1], tools[2]
	require.Equal(t, "exec", string(byteFields(t, exec, 1)[0]))
	custom, ok := varintField(t, exec, 9)
	require.True(t, ok)
	require.Equal(t, uint64(1), custom)
	require.Equal(t, `start: /[\s\S]+/`, string(byteFields(t, exec, 10)[0]))
	require.Equal(t, "lark", string(byteFields(t, exec, 11)[0]))
	require.Empty(t, byteFields(t, exec, 3), "custom 工具不发送 {input} 降级 schema")

	_, ok = varintField(t, wait, 9)
	require.False(t, ok)
	require.NotEmpty(t, byteFields(t, wait, 3))

	_, ok = varintField(t, note, 9)
	require.True(t, ok)
	require.Empty(t, byteFields(t, note, 10), "text 格式只带 custom 标记")

	prompts := byteFields(t, payload, 3)
	require.Len(t, prompts, 3)
	call := byteFields(t, prompts[1], 6)[0]
	require.Equal(t, input, string(byteFields(t, call, 3)[0]), "历史 custom 调用回放原始文本")
	flag, ok := varintField(t, call, 6)
	require.True(t, ok)
	require.Equal(t, uint64(1), flag)
}

func TestResponseWrapsCustomToolCallInput(t *testing.T) {
	raw := "echo hi && printf 'a\"b'\n中文"
	split := len(raw) - 2 // 切在“文”的 UTF-8 中间
	first := bytes.Join([][]byte{field(1, "call_exec"), field(2, "exec"), number(6, 1)}, nil)
	data := bytes.Join([][]byte{
		frame(0, field(6, string(first))),
		frame(0, field(6, string(field(3, raw[:split])))),
		frame(0, field(6, string(field(3, raw[split:])))),
		usageFrame(), frame(2, []byte(`{}`)),
	}, nil)

	resp, err := ConvertChatResponse(upstream(data), "gpt-6-astra", false, false)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	arguments := gjson.GetBytes(body, "choices.0.message.tool_calls.0.function.arguments").String()
	require.Equal(t, raw, gjson.Get(arguments, "input").String())

	resp, err = ConvertChatResponse(upstream(data), "gpt-6-astra", true, false)
	require.NoError(t, err)
	body, err = io.ReadAll(resp.Body)
	require.NoError(t, err)
	state := apicompat.NewChatCompletionsToResponsesStreamState("gpt-6-astra")
	state.CustomTools = map[string]bool{"exec": true}
	var events []apicompat.ResponsesStreamEvent
	for _, line := range strings.Split(string(body), "\n") {
		if !strings.HasPrefix(line, "data: {") {
			continue
		}
		var chunk apicompat.ChatCompletionsChunk
		require.NoError(t, json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &chunk))
		events = append(events, apicompat.ChatCompletionsChunkToResponsesEvents(&chunk, state)...)
	}
	events = append(events, apicompat.FinalizeChatCompletionsResponsesStream(state)...)
	var restored string
	for _, event := range events {
		if event.Type == "response.output_item.done" && event.Item != nil && event.Item.Type == "custom_tool_call" {
			restored = event.Item.Input
		}
	}
	require.Equal(t, raw, restored)
}
