package service

import (
	"bytes"
	"strings"

	"github.com/tidwall/gjson"
)

// normalizeDeepSeekResponsesWebSearchCalls 把历史里的 web_search_call 改写成 DeepSeek
// 原生 Responses 端点能反序列化的形态。
//
// 跨模型切换后（xAI 等上游的托管搜索），历史里的 search 动作只有 `query`，DeepSeek 要求
// `queries`，整轮以 422 "missing field `queries`" 拒绝；粘性会话又会把同一会话一直路由到
// 该账号，导致会话永久不可用。实测 DeepSeek 的口径：
//   - search 必须带 queries（空数组也可），缺失即拒绝：用 query 补齐；
//   - open_page / find_in_page 只要求 url，缺 url 即拒绝；
//   - 缺 action 即拒绝。
//
// 无法补齐的条目只是历史上的搜索记录，直接移除，不影响本轮。
func normalizeDeepSeekResponsesWebSearchCalls(body []byte) ([]byte, bool) {
	if len(body) == 0 || !bytes.Contains(body, []byte(openAIWebSearchCallItemType)) {
		return body, false
	}
	input := parseRawJSONView(body).Get("input")
	if !input.IsArray() || !responsesInputHasInvalidDeepSeekWebSearchCall(input) {
		return body, false
	}

	var reqBody map[string]any
	if err := decodeOpenAIJSONUseNumber(body, &reqBody); err != nil {
		return body, false
	}
	items, ok := reqBody["input"].([]any)
	if !ok {
		return body, false
	}
	rewritten := make([]any, 0, len(items))
	changed := false
	for _, rawItem := range items {
		item, ok := rawItem.(map[string]any)
		if !ok || strings.TrimSpace(firstNonEmptyString(item["type"])) != openAIWebSearchCallItemType {
			rewritten = append(rewritten, rawItem)
			continue
		}
		keep, itemChanged := repairDeepSeekWebSearchCallItem(item)
		changed = changed || itemChanged || !keep
		if keep {
			rewritten = append(rewritten, item)
		}
	}
	if !changed {
		return body, false
	}
	reqBody["input"] = rewritten
	normalized, err := marshalOpenAIUpstreamJSON(reqBody)
	if err != nil {
		return body, false
	}
	return normalized, true
}

// responsesInputHasInvalidDeepSeekWebSearchCall 快判是否需要整体解码改写；
// 判定口径必须与 repairDeepSeekWebSearchCallItem 保持一致。
func responsesInputHasInvalidDeepSeekWebSearchCall(input gjson.Result) bool {
	for _, item := range input.Array() {
		if strings.TrimSpace(item.Get("type").String()) != openAIWebSearchCallItemType {
			continue
		}
		action := item.Get("action")
		if !action.IsObject() {
			return true
		}
		switch strings.TrimSpace(action.Get("type").String()) {
		case "search":
			if !action.Get("queries").IsArray() {
				return true
			}
		case "open_page", "find_in_page":
			if strings.TrimSpace(action.Get("url").String()) == "" {
				return true
			}
		}
	}
	return false
}

// repairDeepSeekWebSearchCallItem 原地补齐单条 web_search_call，返回是否保留与是否改动。
func repairDeepSeekWebSearchCallItem(item map[string]any) (keep bool, changed bool) {
	action, ok := item["action"].(map[string]any)
	if !ok {
		return false, false
	}
	switch strings.TrimSpace(firstNonEmptyString(action["type"])) {
	case "search":
		if _, ok := action["queries"].([]any); ok {
			return true, false
		}
		queries := []any{}
		if query := strings.TrimSpace(firstNonEmptyString(action["query"])); query != "" {
			queries = append(queries, query)
		}
		action["queries"] = queries
		return true, true
	case "open_page", "find_in_page":
		if strings.TrimSpace(firstNonEmptyString(action["url"])) == "" {
			return false, false
		}
	}
	return true, false
}
