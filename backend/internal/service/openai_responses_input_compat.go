package service

import (
	"strings"

	"github.com/tidwall/gjson"
)

const openAIResponsesInputTextMaxChars = 10000000

// sanitizeOpenAIResponsesOrphanToolOutputs removes tool-output items that have
// no matching call or item reference anywhere in the current input. Named
// function outputs without a call ID are standalone inputs, not orphan results.
func sanitizeOpenAIResponsesOrphanToolOutputs(reqBody map[string]any, input []any, hasPreviousResponseID bool) bool {
	if len(input) == 0 || hasPreviousResponseID {
		return false
	}

	toolCallIDs := make(map[string]struct{}, len(input))
	referenceIDs := make(map[string]struct{}, len(input))
	for _, rawItem := range input {
		item, ok := rawItem.(map[string]any)
		if !ok {
			continue
		}
		itemType := strings.TrimSpace(firstNonEmptyString(item["type"]))
		if itemType == "item_reference" {
			if id := strings.TrimSpace(firstNonEmptyString(item["id"])); id != "" {
				referenceIDs[id] = struct{}{}
			}
			continue
		}
		if !isCodexToolCallContextItemType(itemType) {
			continue
		}
		if id := strings.TrimSpace(firstNonEmptyString(item["call_id"], item["id"])); id != "" {
			toolCallIDs[id] = struct{}{}
		}
	}

	modified := false
	normalized := make([]any, 0, len(input))
	for _, rawItem := range input {
		item, ok := rawItem.(map[string]any)
		if !ok || !isCodexToolCallOutputItemType(strings.TrimSpace(firstNonEmptyString(item["type"]))) {
			normalized = append(normalized, rawItem)
			continue
		}

		callID := strings.TrimSpace(firstNonEmptyString(item["call_id"]))
		// Codex sends externally supplied inputs (such as task delegation) as
		// named function outputs without a preceding function call. Preserve
		// their native type, namespace and output instead of silently dropping
		// the request that started the turn.
		if callID == "" && strings.TrimSpace(firstNonEmptyString(item["type"])) == "function_call_output" &&
			strings.TrimSpace(firstNonEmptyString(item["name"])) != "" {
			normalized = append(normalized, rawItem)
			continue
		}
		_, hasToolCall := toolCallIDs[callID]
		_, hasReference := referenceIDs[callID]
		if callID != "" && (hasToolCall || hasReference) {
			normalized = append(normalized, rawItem)
			continue
		}

		modified = true
	}
	if !modified {
		return false
	}
	reqBody["input"] = normalized
	return true
}

// openAIResponsesInputHasOrphanToolOutputs 零拷贝预检 sanitizeOpenAIResponsesOrphanToolOutputs
// 是否会删除条目，判定规则与其保持一致。为 false 时调用方可跳过整体解码：
// OAuth 请求几乎都带 input 数组，带数十 MB 内联图片时每次解码会分配数百 MB。
func openAIResponsesInputHasOrphanToolOutputs(body []byte) bool {
	root := parseRawJSONView(body)
	if gjsonNonEmptyString(root.Get("previous_response_id")) != "" {
		return false
	}
	input := root.Get("input")
	if !input.IsArray() {
		return false
	}

	toolCallIDs := make(map[string]struct{})
	referenceIDs := make(map[string]struct{})
	input.ForEach(func(_, item gjson.Result) bool {
		if !item.IsObject() {
			return true
		}
		itemType := gjsonNonEmptyString(item.Get("type"))
		if itemType == "item_reference" {
			if id := gjsonNonEmptyString(item.Get("id")); id != "" {
				referenceIDs[id] = struct{}{}
			}
			return true
		}
		if !isCodexToolCallContextItemType(itemType) {
			return true
		}
		id := gjsonNonEmptyString(item.Get("call_id"))
		if id == "" {
			id = gjsonNonEmptyString(item.Get("id"))
		}
		if id != "" {
			toolCallIDs[id] = struct{}{}
		}
		return true
	})

	orphan := false
	input.ForEach(func(_, item gjson.Result) bool {
		if !item.IsObject() {
			return true
		}
		itemType := gjsonNonEmptyString(item.Get("type"))
		if !isCodexToolCallOutputItemType(itemType) {
			return true
		}
		callID := gjsonNonEmptyString(item.Get("call_id"))
		if callID == "" && itemType == "function_call_output" && gjsonNonEmptyString(item.Get("name")) != "" {
			return true
		}
		_, hasToolCall := toolCallIDs[callID]
		_, hasReference := referenceIDs[callID]
		if callID != "" && (hasToolCall || hasReference) {
			return true
		}
		orphan = true
		return false
	})
	return orphan
}

// gjsonNonEmptyString 与 firstNonEmptyString 对单个值的语义一致：仅取字符串并去除首尾空白。
func gjsonNonEmptyString(value gjson.Result) string {
	if value.Type != gjson.String {
		return ""
	}
	return strings.TrimSpace(value.String())
}

func truncateOpenAIResponsesInputText(_ map[string]any) bool {
	// Do not silently rewrite client or tool output. If an upstream enforces a
	// text limit, forwarding the original value preserves its explicit error for
	// the client and the normal Ops error pipeline. This compatibility shim is
	// retained until the two callers can remove the old mutation hook together.
	return false
}

func openAIResponsesInputMayNeedTruncation(_ []byte) bool {
	// See truncateOpenAIResponsesInputText. Returning false also avoids decoding
	// very large bodies solely for a mutation that must not happen.
	return false
}
