package service

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSummarizeOpenAIResponsesReasoningInput(t *testing.T) {
	body := []byte(`{"input":[` +
		`{"type":"message","role":"user","content":"go"},` +
		`{"type":"reasoning","content":[{"type":"reasoning_text","text":"think"}],"summary":[]},` +
		`{"type":"message","role":"assistant","phase":"commentary","content":[{"type":"output_text","text":"ok"}]},` +
		`{"type":"function_call","call_id":"c1","name":"search","arguments":"{}"},` +
		`{"type":"function_call_output","call_id":"c1","output":"done"}]}`)

	summary, unguarded := summarizeOpenAIResponsesReasoningInput(body, 48)
	require.Empty(t, unguarded, "有前置明文 reasoning 时不应标记为未保护")
	require.Contains(t, summary, "input_items=5")
	require.Contains(t, summary, "1:reasoning(plain)")
	require.Contains(t, summary, "2:message/assistant(commentary)")
	require.Contains(t, summary, "3:function_call(search)")
}

func TestSummarizeOpenAIResponsesReasoningInputFlagsUnguardedAssistant(t *testing.T) {
	body := []byte(`{"input":[` +
		`{"type":"message","role":"user","content":"go"},` +
		`{"type":"message","role":"assistant","content":[{"type":"output_text","text":""}]},` +
		`{"type":"reasoning","content":[{"type":"reasoning_text","text":""}],"summary":[]}]}`)

	summary, unguarded := summarizeOpenAIResponsesReasoningInput(body, 48)
	require.Equal(t, []int{1}, unguarded)
	require.Contains(t, summary, "1:message/assistant")
	require.Contains(t, summary, "2:reasoning(no-plain)")
}

// 下游形态一旦省略 type 字段，生产补齐（要求 type=message）会漏掉它；摘要用「有 role 即
// message」的宽松判定，必须在日志里把它标成未保护。
func TestSummarizeOpenAIResponsesReasoningInputTreatsRoleWithoutTypeAsMessage(t *testing.T) {
	body := []byte(`{"input":[{"role":"user","content":"go"},{"role":"assistant","content":[{"type":"output_text","text":""}]}]}`)

	summary, unguarded := summarizeOpenAIResponsesReasoningInput(body, 48)
	require.Equal(t, []int{1}, unguarded)
	require.Contains(t, summary, "1:message/assistant")
}

func TestSummarizeOpenAIResponsesReasoningInputTruncatesLongSequences(t *testing.T) {
	items := make([]string, 0, 60)
	for i := 0; i < 60; i++ {
		items = append(items, `{"type":"function_call","call_id":"c","name":"run","arguments":"{}"}`)
	}

	summary, _ := summarizeOpenAIResponsesReasoningInput([]byte(`{"input":[`+strings.Join(items, ",")+`]}`), 10)
	require.Contains(t, summary, "input_items=60")
	require.Contains(t, summary, "...(+50)")
}

func TestIsOpenAIReasoningPassbackError(t *testing.T) {
	deepseek := &Account{Platform: PlatformDeepseek}
	require.True(t, isOpenAIReasoningPassbackError(deepseek, 400,
		"The `reasoning_text` in the thinking mode must be passed back to the API."))
	require.True(t, isOpenAIReasoningPassbackError(deepseek, 400,
		"The `reasoning_content` in the thinking mode must be passed back to the API"))
	require.False(t, isOpenAIReasoningPassbackError(deepseek, 400, "No tool output found for tool call call_1."))
	require.False(t, isOpenAIReasoningPassbackError(deepseek, 500,
		"The `reasoning_text` in the thinking mode must be passed back to the API."))
	// 只对 DeepSeek 账号触发，避免其它平台产生无关日志。
	for _, platform := range []string{PlatformOpenAI, PlatformKimi, PlatformZhipu} {
		require.False(t, isOpenAIReasoningPassbackError(&Account{Platform: platform}, 400,
			"The `reasoning_text` in the thinking mode must be passed back to the API."))
	}
	require.False(t, isOpenAIReasoningPassbackError(nil, 400,
		"The `reasoning_text` in the thinking mode must be passed back to the API."))
}
