package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/pkg/claude"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// stripMessageCacheControl 移除 $.messages[*].content[*].cache_control。
// 与 Parrot _strip_message_cache_control 语义一致。
//
// 旧策略为什么整体清空：客户端（特别是 Claude Code）经常把 cache_control 打在
// "当前最后一条 user message" 上；下一轮对话 messages 追加后，原本的最后一条
// 变成中间某条，cache_control 还挂着就导致"前缀签名变化"，破坏缓存命中。
// 统一由代理重新打断点（addMessageCacheBreakpoints）才能在多轮间稳定。
func stripMessageCacheControl(body []byte) []byte {
	messages := gjson.GetBytes(body, "messages")
	if !messages.IsArray() {
		return body
	}
	msgIdx := -1
	messages.ForEach(func(_, msg gjson.Result) bool {
		msgIdx++
		content := msg.Get("content")
		if !content.IsArray() {
			return true
		}
		blockIdx := -1
		content.ForEach(func(_, block gjson.Result) bool {
			blockIdx++
			if !block.Get("cache_control").Exists() {
				return true
			}
			path := fmt.Sprintf("messages.%d.content.%d.cache_control", msgIdx, blockIdx)
			if next, err := sjson.DeleteBytes(body, path); err == nil {
				body = next
			}
			return true
		})
		return true
	})
	return body
}

// addMessageCacheBreakpoints 在 messages 上注入两个稳定的 cache 断点：
//  1. 最后一条 message
//  2. 当 messages 数量 ≥ 4 时，倒数第二个 role=user 的 message
//
// 与 Parrot add_cache_breakpoints 一致。两个断点 + system prompt block 的断点
// + tools[-1] 的断点共同构成最多 4 个断点（Anthropic 上限）。
//
// cache_control ttl 策略：
//   - 若目标 block 已有 cache_control.ttl → 不覆盖
//   - 否则写入 {"type":"ephemeral","ttl": claude.DefaultCacheControlTTL}
//
// 调用前应先 stripMessageCacheControl 以保证幂等和稳定。
func addMessageCacheBreakpoints(body []byte) []byte {
	messages := gjson.GetBytes(body, "messages")
	if !messages.IsArray() {
		return body
	}
	arr := messages.Array()
	if len(arr) == 0 {
		return body
	}

	body = injectCacheControlOnLastContentBlock(body, len(arr)-1, &arr[len(arr)-1])

	if len(arr) >= 4 {
		userCount := 0
		for i := len(arr) - 1; i >= 0; i-- {
			if arr[i].Get("role").String() != "user" {
				continue
			}
			userCount++
			if userCount == 2 {
				body = injectCacheControlOnLastContentBlock(body, i, &arr[i])
				break
			}
		}
	}

	return body
}

// addSystemCacheBreakpoint 在 system 的最后一个块上注入 cache 断点。上游按
// tools → system → messages 渲染，这个断点同时覆盖 tools 与 system 前缀。
// 空白的 string system 保持原样：上游拒绝带 cache_control 的空文本块。
func addSystemCacheBreakpoint(body []byte) []byte {
	system := gjson.GetBytes(body, "system")
	if system.Type == gjson.String && strings.TrimSpace(system.String()) == "" {
		return body
	}
	return injectCacheControlOnLastBlock(body, "system", system)
}

// addConvertedClaudeCacheBreakpoints 给协议转换（Responses / Chat Completions →
// Anthropic Messages）产出的请求体补 cache 断点。这两种入站协议没有 cache_control，
// 转换结果是零断点，而 API Key 上游只认显式的块级断点，不打就完全不命中缓存。
//
// 断点位置：tools 末项、system 末块、messages 尾部（末条消息，以及消息数 ≥ 4 时
// 倒数第二条 user 消息），合计不超过 4 个。
//
// 只对映射后的上游模型是 Claude 的请求生效：DeepSeek / Kimi / GLM 等 Anthropic
// 兼容端点是否接受 cache_control 没有验证过。OAuth 账号的断点由 Claude Code 伪装
// 链路（applyClaudeCodeOAuthMimicryToBody）负责，调用方不要对它再调用本函数。
func addConvertedClaudeCacheBreakpoints(body []byte, upstreamModel string) []byte {
	if platform, ok := DetectModelPlatform(upstreamModel); !ok || platform != PlatformAnthropic {
		return body
	}
	body = applyToolsLastCacheBreakpoint(body)
	body = addSystemCacheBreakpoint(body)
	return addMessageCacheBreakpoints(body)
}

// rewriteMessageCacheControlIfEnabled 按系统设置决定是否执行旧版 messages 缓存断点改写。
func (s *GatewayService) rewriteMessageCacheControlIfEnabled(ctx context.Context, body []byte) []byte {
	if s == nil || !s.isRewriteMessageCacheControlEnabled(ctx) {
		return body
	}
	body = stripMessageCacheControl(body)
	return addMessageCacheBreakpoints(body)
}

func (s *GatewayService) isRewriteMessageCacheControlEnabled(ctx context.Context) bool {
	if s == nil {
		return false
	}
	if s.settingService != nil {
		return s.settingService.IsRewriteMessageCacheControlEnabled(ctx)
	}
	return false
}

// injectCacheControlOnLastContentBlock 把 cache_control 断点打在 messages[idx]
// 的最后一个 content block 上。若 content 是 string，先升级成单块 text 数组
// （对齐 Parrot _inject_cache_on_msg 的行为）。
//
// msg 是调用方已持有的 gjson.Result 快照，用于省一次 GetBytes。
func injectCacheControlOnLastContentBlock(body []byte, idx int, msg *gjson.Result) []byte {
	return injectCacheControlOnLastBlock(body, fmt.Sprintf("messages.%d.content", idx), msg.Get("content"))
}

// injectCacheControlOnLastBlock 把 cache_control 断点打在 path 处内容的最后一个块上。
// content 是 path 处的值快照：string 会升级成单块 text 数组，数组取末块；末块已有
// 带 ttl 的断点时不动，缺 ttl 时只补默认 ttl。
func injectCacheControlOnLastBlock(body []byte, path string, content gjson.Result) []byte {
	if content.Type == gjson.String {
		text := content.String()
		blockRaw := fmt.Sprintf(
			`[{"type":"text","text":%s,"cache_control":{"type":"ephemeral","ttl":%q}}]`,
			mustJSONString(text), claude.DefaultCacheControlTTL,
		)
		if next, err := sjson.SetRawBytes(body, path, []byte(blockRaw)); err == nil {
			body = next
		}
		return body
	}

	if !content.IsArray() {
		return body
	}
	contentArr := content.Array()
	if len(contentArr) == 0 {
		return body
	}
	lastBlockIdx := len(contentArr) - 1
	lastBlock := contentArr[lastBlockIdx]

	if cc := lastBlock.Get("cache_control"); cc.Exists() && cc.Get("ttl").String() != "" {
		return body
	}

	pathPrefix := fmt.Sprintf("%s.%d.cache_control", path, lastBlockIdx)
	existingCC := lastBlock.Get("cache_control")
	if existingCC.Exists() {
		if next, err := sjson.SetBytes(body, pathPrefix+".ttl", claude.DefaultCacheControlTTL); err == nil {
			body = next
		}
		return body
	}
	raw := fmt.Sprintf(`{"type":"ephemeral","ttl":%q}`, claude.DefaultCacheControlTTL)
	if next, err := sjson.SetRawBytes(body, pathPrefix, []byte(raw)); err == nil {
		body = next
	}
	return body
}

// mustJSONString 把一个 Go string 序列化为合法 JSON string（含引号），
// 用于 sjson.SetRawBytes 场景下手工拼 JSON。
func mustJSONString(s string) string {
	// Go string quoting can emit non-JSON escapes such as \x7f or \a.
	// Marshaling a string cannot fail.
	encoded, _ := json.Marshal(s)
	return string(encoded)
}
