package service

import (
	"bytes"
	"strconv"
	"strings"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// deepSeekAnthropicThinkingPlaceholderBlock 是补给 DeepSeek Anthropic 端点的占位
// thinking 块。明文沿用 Chat Completions 路径的 deepSeekChatReasoningPlaceholderText
// （单个空格）：DeepSeek 官方只校验块是否存在，空串与空格都放行；空格避免中间
// 聚合层把空串规整成"无 thinking"。
var deepSeekAnthropicThinkingPlaceholderBlock = `{"type":"thinking","thinking":` +
	strconv.Quote(deepSeekChatReasoningPlaceholderText) + `,"signature":""}`

// EnsureDeepSeekAnthropicThinkingPlaceholders 给缺 thinking 的 tool_use assistant
// 消息补占位 thinking 块，修复 DeepSeek Anthropic 端点的 400：
// "The `content[].thinking` in the thinking mode must be passed back to the API"。
//
// DeepSeek 思考模式下，当前轮（最后一条真实 user 消息之后）任一带 tool_use 的
// assistant 消息缺 thinking 块即拒收；而模型自己在同一轮的链式工具调用里常常不
// 输出 thinking，客户端（Claude Code 等）如实回放后，下一请求必然 400。OpenCode
// Go 按请求分流到不同后端，只有部分后端执行该校验，所以表现为偶发。
//
// 只处理含 tool_use 的 assistant 消息（不动纯文本 assistant，避免改写 prefill），
// 且不区分轮次：历史轮次的 thinking DeepSeek 会忽略，统一补齐使同一会话每次
// 改写结果一致，前缀缓存不因跨轮而失效。客户端显式关闭 thinking 时不处理。
// 无需改写时原样返回 body。
func EnsureDeepSeekAnthropicThinkingPlaceholders(body []byte, upstreamModel string) []byte {
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(upstreamModel)), "deepseek-") {
		return body
	}
	if !bytes.Contains(body, []byte(`"tool_use"`)) {
		return body
	}
	if gjson.GetBytes(body, "thinking.type").String() == "disabled" {
		return body
	}
	messages := gjson.GetBytes(body, "messages")
	if !messages.IsArray() {
		return body
	}

	updated := body
	changed := false
	for i, msg := range messages.Array() {
		if msg.Get("role").String() != "assistant" {
			continue
		}
		content := msg.Get("content")
		if !content.IsArray() || !assistantNeedsThinkingPlaceholder(content) {
			continue
		}
		raw := strings.TrimSpace(content.Raw)
		if !strings.HasPrefix(raw, "[") {
			continue
		}
		patched := "[" + deepSeekAnthropicThinkingPlaceholderBlock + "," + raw[1:]
		next, err := sjson.SetRawBytes(updated, "messages."+strconv.Itoa(i)+".content", []byte(patched))
		if err != nil {
			return body
		}
		updated = next
		changed = true
	}
	if !changed {
		return body
	}
	return updated
}

// assistantNeedsThinkingPlaceholder 判定 assistant content 含 tool_use 且没有任何
// thinking / redacted_thinking 块。
func assistantNeedsThinkingPlaceholder(content gjson.Result) bool {
	hasToolUse := false
	for _, block := range content.Array() {
		switch block.Get("type").String() {
		case "thinking", "redacted_thinking":
			return false
		case "tool_use":
			hasToolUse = true
		}
	}
	return hasToolUse
}
