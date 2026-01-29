package antigravity

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

var (
	sessionRand      = rand.New(rand.NewSource(time.Now().UnixNano()))
	sessionRandMutex sync.Mutex
)

// generateStableSessionID 基于用户消息内容生成稳定的 session ID
func generateStableSessionID(contents []GeminiContent) string {
	// 查找第一个 user 消息的文本
	for _, content := range contents {
		if content.Role == "user" && len(content.Parts) > 0 {
			if text := content.Parts[0].Text; text != "" {
				h := sha256.Sum256([]byte(text))
				n := int64(binary.BigEndian.Uint64(h[:8])) & 0x7FFFFFFFFFFFFFFF
				return "-" + strconv.FormatInt(n, 10)
			}
		}
	}
	// 回退：生成随机 session ID
	sessionRandMutex.Lock()
	n := sessionRand.Int63n(9_000_000_000_000_000_000)
	sessionRandMutex.Unlock()
	return "-" + strconv.FormatInt(n, 10)
}

type TransformOptions struct {
	EnableIdentityPatch bool
	// IdentityPatch 可选：自定义注入到 systemInstruction 开头的身份防护提示词；
	// 为空时使用默认模板（包含 [IDENTITY_PATCH] 及 SYSTEM_PROMPT_BEGIN 标记）。
	IdentityPatch string
	EnableMCPXML  bool
}

func DefaultTransformOptions() TransformOptions {
	return TransformOptions{
		EnableIdentityPatch: true,
		EnableMCPXML:        true,
	}
}

// webSearchFallbackModel web_search 请求使用的降级模型
const webSearchFallbackModel = "gemini-2.5-flash"

// TransformClaudeToGemini 将 Claude 请求转换为 v1internal Gemini 格式
func TransformClaudeToGemini(claudeReq *ClaudeRequest, projectID, mappedModel string) ([]byte, error) {
	return TransformClaudeToGeminiWithOptions(claudeReq, projectID, mappedModel, DefaultTransformOptions())
}

// TransformClaudeToGeminiWithOptions 将 Claude 请求转换为 v1internal Gemini 格式（可配置身份补丁等行为）
func TransformClaudeToGeminiWithOptions(claudeReq *ClaudeRequest, projectID, mappedModel string, opts TransformOptions) ([]byte, error) {
	// 用于存储 tool_use id -> name 映射
	toolIDToName := make(map[string]string)

	// 检测是否有 web_search 工具
	hasWebSearchTool := hasWebSearchTool(claudeReq.Tools)
	requestType := "agent"
	targetModel := mappedModel
	if hasWebSearchTool {
		requestType = "web_search"
		if targetModel != webSearchFallbackModel {
			targetModel = webSearchFallbackModel
		}
	}

	// 检测是否启用 thinking
	isThinkingEnabled := claudeReq.Thinking != nil && claudeReq.Thinking.Type == "enabled"

	// 只有 Gemini 模型支持 dummy thought workaround
	// Claude 模型通过 Vertex/Google API 需要有效的 thought signatures
	allowDummyThought := strings.HasPrefix(targetModel, "gemini-")

	// 对 Claude 模型：工具调用缺少 signature 时，禁用 thinking 避免上游校验失败
	if isThinkingEnabled && !allowDummyThought && hasToolUseWithoutSignature(claudeReq.Messages) {
		isThinkingEnabled = false
	}

	// 1. 构建 contents
	contents, strippedThinking, err := buildContents(claudeReq.Messages, toolIDToName, isThinkingEnabled, allowDummyThought)
	if err != nil {
		return nil, fmt.Errorf("build contents: %w", err)
	}

	// 2. 构建 systemInstruction
	systemInstruction := buildSystemInstruction(claudeReq.System, claudeReq.Model, opts, claudeReq.Tools)

	// 3. 构建 generationConfig
	reqForConfig := claudeReq
	if !isThinkingEnabled || strippedThinking {
		// If we had to downgrade thinking blocks to plain text due to missing/invalid signatures,
		// disable upstream thinking mode to avoid signature/structure validation errors.
		reqCopy := *claudeReq
		reqCopy.Thinking = nil
		reqForConfig = &reqCopy
	}
	if targetModel != "" && targetModel != reqForConfig.Model {
		reqCopy := *reqForConfig
		reqCopy.Model = targetModel
		reqForConfig = &reqCopy
	}
	generationConfig := buildGenerationConfig(reqForConfig)

	// 4. 构建 tools
	tools := buildTools(claudeReq.Tools)

	// 5. 构建内部请求
	innerRequest := GeminiRequest{
		Contents: contents,
		// 总是设置 toolConfig，与官方客户端一致
		ToolConfig: &GeminiToolConfig{
			FunctionCallingConfig: &GeminiFunctionCallingConfig{
				Mode: "VALIDATED",
			},
		},
		// 总是生成 sessionId，基于用户消息内容
		SessionID: generateStableSessionID(contents),
	}

	if systemInstruction != nil {
		innerRequest.SystemInstruction = systemInstruction
	}
	if generationConfig != nil {
		innerRequest.GenerationConfig = generationConfig
	}
	if len(tools) > 0 {
		innerRequest.Tools = tools
	}

	// 如果提供了 metadata.user_id，优先使用
	if claudeReq.Metadata != nil && claudeReq.Metadata.UserID != "" {
		innerRequest.SessionID = claudeReq.Metadata.UserID
	}

	// 6. 包装为 v1internal 请求
	v1Req := V1InternalRequest{
		Project:     projectID,
		RequestID:   "agent-" + uuid.New().String(),
		UserAgent:   "antigravity", // 固定值，与官方客户端一致
		RequestType: requestType,
		Model:       targetModel,
		Request:     innerRequest,
	}

	return json.Marshal(v1Req)
}

// antigravityIdentity Antigravity identity 提示词
const antigravityIdentity = `<identity>
You are Antigravity, a powerful agentic AI coding assistant designed by the Google Deepmind team working on Advanced Agentic Coding.
You are pair programming with a USER to solve their coding task. The task may require creating a new codebase, modifying or debugging an existing codebase, or simply answering a question.
The USER will send you requests, which you must always prioritize addressing. Along with each USER request, we will attach additional metadata about their current state, such as what files they have open and where their cursor is.
This information may or may not be relevant to the coding task, it is up for you to decide.
</identity>
<communication_style>
- **Proactiveness**. As an agent, you are allowed to be proactive, but only in the course of completing the user's task. For example, if the user asks you to add a new component, you can edit the code, verify build and test statuses, and take any other obvious follow-up actions, such as performing additional research. However, avoid surprising the user. For example, if the user asks HOW to approach something, you should answer their question and instead of jumping into editing a file.</communication_style>`

func defaultIdentityPatch(_ string) string {
	return antigravityIdentity
}

// GetDefaultIdentityPatch 返回默认的 Antigravity 身份提示词
func GetDefaultIdentityPatch() string {
	return antigravityIdentity
}

// mcpXMLProtocol MCP XML 工具调用协议（与 Antigravity-Manager 保持一致）
const mcpXMLProtocol = `
==== MCP XML 工具调用协议 (Workaround) ====
当你需要调用名称以 ` + "`mcp__`" + ` 开头的 MCP 工具时：
1) 优先尝试 XML 格式调用：输出 ` + "`<mcp__tool_name>{\"arg\":\"value\"}</mcp__tool_name>`" + `。
2) 必须直接输出 XML 块，无需 markdown 包装，内容为 JSON 格式的入参。
3) 这种方式具有更高的连通性和容错性，适用于大型结果返回场景。
===========================================`

// hasMCPTools 检测是否有 mcp__ 前缀的工具
func hasMCPTools(tools []ClaudeTool) bool {
	for _, tool := range tools {
		if strings.HasPrefix(tool.Name, "mcp__") {
			return true
		}
	}
	return false
}

// filterOpenCodePrompt 过滤 OpenCode 默认提示词，只保留用户自定义指令
func filterOpenCodePrompt(text string) string {
	if !strings.Contains(text, "You are an interactive CLI tool") {
		return text
	}
	// 提取 "Instructions from:" 及之后的部分
	if idx := strings.Index(text, "Instructions from:"); idx >= 0 {
		return text[idx:]
	}
	// 如果没有自定义指令，返回空
	return ""
}

// buildSystemInstruction 构建 systemInstruction（与 Antigravity-Manager 保持一致）
func buildSystemInstruction(system json.RawMessage, modelName string, opts TransformOptions, tools []ClaudeTool) *GeminiContent {
	var parts []GeminiPart

	// 先解析用户的 system prompt，检测是否已包含 Antigravity identity
	userHasAntigravityIdentity := false
	var userSystemParts []GeminiPart

	if len(system) > 0 {
		// 尝试解析为字符串
		var sysStr string
		if err := json.Unmarshal(system, &sysStr); err == nil {
			if strings.TrimSpace(sysStr) != "" {
				if strings.Contains(sysStr, "You are Antigravity") {
					userHasAntigravityIdentity = true
				}
				// 过滤 OpenCode 默认提示词
				filtered := filterOpenCodePrompt(sysStr)
				if filtered != "" {
					userSystemParts = append(userSystemParts, GeminiPart{Text: filtered})
				}
			}
		} else {
			// 尝试解析为数组
			var sysBlocks []SystemBlock
			if err := json.Unmarshal(system, &sysBlocks); err == nil {
				for _, block := range sysBlocks {
					if block.Type == "text" && strings.TrimSpace(block.Text) != "" {
						if strings.Contains(block.Text, "You are Antigravity") {
							userHasAntigravityIdentity = true
						}
						// 过滤 OpenCode 默认提示词
						filtered := filterOpenCodePrompt(block.Text)
						if filtered != "" {
							userSystemParts = append(userSystemParts, GeminiPart{Text: filtered})
						}
					}
				}
			}
		}
	}

	// 仅在用户未提供 Antigravity identity 时注入
	if opts.EnableIdentityPatch && !userHasAntigravityIdentity {
		identityPatch := strings.TrimSpace(opts.IdentityPatch)
		if identityPatch == "" {
			identityPatch = defaultIdentityPatch(modelName)
		}
		parts = append(parts, GeminiPart{Text: identityPatch})
	}

	// 添加用户的 system prompt
	parts = append(parts, userSystemParts...)

	// 检测是否有 MCP 工具，如有且启用了 MCP XML 注入则注入 XML 调用协议
	if opts.EnableMCPXML && hasMCPTools(tools) {
		parts = append(parts, GeminiPart{Text: mcpXMLProtocol})
	}

	// 如果用户没有提供 Antigravity 身份，添加结束标记
	if !userHasAntigravityIdentity {
		parts = append(parts, GeminiPart{Text: "\n--- [SYSTEM_PROMPT_END] ---"})
	}

	if len(parts) == 0 {
		return nil
	}

	return &GeminiContent{
		Role:  "user",
		Parts: parts,
	}
}

// buildContents 构建 contents
func buildContents(messages []ClaudeMessage, toolIDToName map[string]string, isThinkingEnabled, allowDummyThought bool) ([]GeminiContent, bool, error) {
	var contents []GeminiContent
	strippedThinking := false
	lastThoughtSignature := ""

	// [Elastic-Recovery] 追踪待处理的 tool_use id
	// 用于检测用户中断工具执行的场景（tool_use 后没有对应的 tool_result）
	pendingToolUseIDs := make(map[string]bool)

	// 预扫描：收集所有已存在的 tool_result id，避免重复注入
	existingToolResultIDs := make(map[string]bool)
	for _, msg := range messages {
		var blocks []ContentBlock
		if err := json.Unmarshal(msg.Content, &blocks); err == nil {
			for _, block := range blocks {
				if block.Type == "tool_result" && block.ToolUseID != "" {
					existingToolResultIDs[block.ToolUseID] = true
				}
			}
		}
	}

	for i, msg := range messages {
		role := msg.Role
		if role == "assistant" {
			role = "model"
		}

		// [Elastic-Recovery] 处理 user 消息前，检查是否有未匹配的 tool_use
		// 如果有，注入占位的 tool_result
		if role == "user" && len(pendingToolUseIDs) > 0 {
			var syntheticParts []GeminiPart
			for toolID := range pendingToolUseIDs {
				// 跳过已存在 tool_result 的
				if existingToolResultIDs[toolID] {
					continue
				}
				funcName := toolID
				if name, ok := toolIDToName[toolID]; ok {
					funcName = name
				}
				log.Printf("[Elastic-Recovery] Injecting missing tool_result for tool_use_id: %s", toolID)
				syntheticParts = append(syntheticParts, GeminiPart{
					FunctionResponse: &GeminiFunctionResponse{
						Name: funcName,
						Response: map[string]any{
							"result": "Tool execution interrupted. No result provided.",
						},
						ID: toolID,
					},
				})
			}
			// 如果有需要注入的，先作为一个 user 消息添加
			if len(syntheticParts) > 0 {
				contents = append(contents, GeminiContent{
					Role:  "user",
					Parts: syntheticParts,
				})
			}
			// 清空待处理列表
			pendingToolUseIDs = make(map[string]bool)
		}

		parts, strippedThisMsg, err := buildParts(msg.Content, toolIDToName, allowDummyThought, isThinkingEnabled, &lastThoughtSignature)
		if err != nil {
			return nil, false, fmt.Errorf("build parts for message %d: %w", i, err)
		}
		if strippedThisMsg {
			strippedThinking = true
		}

		// [Elastic-Recovery] 收集当前消息中的 tool_use 和 tool_result
		var blocks []ContentBlock
		if err := json.Unmarshal(msg.Content, &blocks); err == nil {
			for _, block := range blocks {
				if block.Type == "tool_use" && block.ID != "" {
					pendingToolUseIDs[block.ID] = true
				} else if block.Type == "tool_result" && block.ToolUseID != "" {
					delete(pendingToolUseIDs, block.ToolUseID)
				}
			}
		}

		// 只有 Gemini 模型支持 dummy thinking block workaround
		// 只对最后一条 assistant 消息添加（Pre-fill 场景）
		// 历史 assistant 消息不能添加没有 signature 的 dummy thinking block
		if allowDummyThought && role == "model" && isThinkingEnabled && i == len(messages)-1 {
			hasThoughtPart := false
			for _, p := range parts {
				if p.Thought {
					hasThoughtPart = true
					break
				}
			}
			if !hasThoughtPart && len(parts) > 0 {
				// 在开头添加 dummy thinking block
				parts = append([]GeminiPart{{
					Text:             "Thinking...",
					Thought:          true,
					ThoughtSignature: dummyThoughtSignature,
				}}, parts...)
			}
		}

		if len(parts) == 0 {
			continue
		}

		contents = append(contents, GeminiContent{
			Role:  role,
			Parts: parts,
		})
	}

	// [Elastic-Recovery] 处理最后一条消息后仍有未匹配的 tool_use（最后一条是 assistant 消息且有 tool_use）
	// 这种情况下，user 消息（最后一条）可能没有 tool_result，需要合并注入
	if len(pendingToolUseIDs) > 0 && len(contents) > 0 {
		lastContent := &contents[len(contents)-1]
		if lastContent.Role == "user" {
			for toolID := range pendingToolUseIDs {
				if existingToolResultIDs[toolID] {
					continue
				}
				funcName := toolID
				if name, ok := toolIDToName[toolID]; ok {
					funcName = name
				}
				log.Printf("[Elastic-Recovery] Prepending missing tool_result to last user message for tool_use_id: %s", toolID)
				// 在 user 消息开头插入
				lastContent.Parts = append([]GeminiPart{{
					FunctionResponse: &GeminiFunctionResponse{
						Name: funcName,
						Response: map[string]any{
							"result": "Tool execution interrupted. No result provided.",
						},
						ID: toolID,
					},
				}}, lastContent.Parts...)
			}
		}
	}

	return contents, strippedThinking, nil
}

const (
	thoughtSignatureMinLenEnv     = "GATEWAY_ANTIGRAVITY_THOUGHT_SIGNATURE_MIN_LEN"
	defaultThoughtSignatureMinLen = 20
)

func minThoughtSignatureLen() int {
	raw := strings.TrimSpace(os.Getenv(thoughtSignatureMinLenEnv))
	if raw == "" {
		return defaultThoughtSignatureMinLen
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 {
		return defaultThoughtSignatureMinLen
	}
	return value
}

func normalizeThoughtSignature(sig string) string {
	trimmed := strings.TrimSpace(sig)
	if trimmed == "" || trimmed == dummyThoughtSignature {
		return trimmed
	}
	if idx := strings.Index(trimmed, "#"); idx > 0 {
		prefix := strings.ToLower(strings.TrimSpace(trimmed[:idx]))
		if prefix == "claude" || prefix == "gemini" {
			return strings.TrimSpace(trimmed[idx+1:])
		}
	}
	return trimmed
}

func isValidThoughtSignature(sig string) bool {
	normalized := normalizeThoughtSignature(sig)
	return len(normalized) >= minThoughtSignatureLen() && normalized != dummyThoughtSignature
}

// hasToolUseWithoutSignature 检测是否存在无法回填签名的 tool_use
func hasToolUseWithoutSignature(messages []ClaudeMessage) bool {
	lastSig := ""
	for _, msg := range messages {
		var blocks []ContentBlock
		if err := json.Unmarshal(msg.Content, &blocks); err != nil {
			continue
		}
		for _, block := range blocks {
			switch block.Type {
			case "thinking":
				if sig := normalizeThoughtSignature(block.Signature); isValidThoughtSignature(sig) {
					lastSig = sig
				}
			case "tool_use":
				if sig := normalizeThoughtSignature(block.Signature); isValidThoughtSignature(sig) {
					lastSig = sig
					continue
				}
				if !isValidThoughtSignature(lastSig) {
					return true
				}
			}
		}
	}
	return false
}

// dummyThoughtSignature 用于跳过 Gemini 3 thought_signature 验证
// 参考: https://ai.google.dev/gemini-api/docs/thought-signatures
const dummyThoughtSignature = "skip_thought_signature_validator"

// buildParts 构建消息的 parts
// allowDummyThought: 只有 Gemini 模型支持 dummy thought signature
func buildParts(content json.RawMessage, toolIDToName map[string]string, allowDummyThought, isThinkingEnabled bool, lastThoughtSignature *string) ([]GeminiPart, bool, error) {
	var parts []GeminiPart
	strippedThinking := false

	// 尝试解析为字符串
	var textContent string
	if err := json.Unmarshal(content, &textContent); err == nil {
		if textContent != "(no content)" && strings.TrimSpace(textContent) != "" {
			parts = append(parts, GeminiPart{Text: strings.TrimSpace(textContent)})
		}
		return parts, false, nil
	}

	// 解析为内容块数组
	var blocks []ContentBlock
	if err := json.Unmarshal(content, &blocks); err != nil {
		return nil, false, fmt.Errorf("parse content blocks: %w", err)
	}

	for _, block := range blocks {
		switch block.Type {
		case "text":
			if block.Text != "(no content)" && strings.TrimSpace(block.Text) != "" {
				parts = append(parts, GeminiPart{Text: block.Text})
			}

		case "thinking":
			if !isThinkingEnabled {
				if strings.TrimSpace(block.Thinking) != "" {
					parts = append(parts, GeminiPart{Text: block.Thinking})
				}
				strippedThinking = true
				continue
			}
			part := GeminiPart{
				Text:    block.Thinking,
				Thought: true,
			}
			// 保留原有 signature（Claude 模型需要有效的 signature）
			if sig := normalizeThoughtSignature(block.Signature); isValidThoughtSignature(sig) {
				part.ThoughtSignature = sig
				if lastThoughtSignature != nil {
					*lastThoughtSignature = sig
				}
			} else if !allowDummyThought {
				// Claude 模型需要有效 signature；在缺失时降级为普通文本，并在上层禁用 thinking mode。
				if strings.TrimSpace(block.Thinking) != "" {
					parts = append(parts, GeminiPart{Text: block.Thinking})
				}
				strippedThinking = true
				continue
			} else {
				// Gemini 模型使用 dummy signature
				part.ThoughtSignature = dummyThoughtSignature
			}
			parts = append(parts, part)

		case "image":
			if block.Source != nil && block.Source.Type == "base64" {
				parts = append(parts, GeminiPart{
					InlineData: &GeminiInlineData{
						MimeType: block.Source.MediaType,
						Data:     block.Source.Data,
					},
				})
			}

		case "tool_use":
			// 存储 id -> name 映射
			if block.ID != "" && block.Name != "" {
				toolIDToName[block.ID] = block.Name
			}

			part := GeminiPart{
				FunctionCall: &GeminiFunctionCall{
					Name: block.Name,
					Args: block.Input,
					ID:   block.ID,
				},
			}
			// tool_use 的 signature 处理：
			// - Gemini 模型：使用 dummy signature（跳过 thought_signature 校验）
			// - Claude 模型：透传上游返回的真实 signature（Vertex/Google 需要完整签名链路）
			if allowDummyThought && isThinkingEnabled {
				part.ThoughtSignature = dummyThoughtSignature
			} else if isThinkingEnabled {
				if sig := normalizeThoughtSignature(block.Signature); isValidThoughtSignature(sig) {
					part.ThoughtSignature = sig
					if lastThoughtSignature != nil {
						*lastThoughtSignature = sig
					}
				}
			} else if isThinkingEnabled && lastThoughtSignature != nil && isValidThoughtSignature(*lastThoughtSignature) {
				part.ThoughtSignature = *lastThoughtSignature
			}
			parts = append(parts, part)

		case "tool_result":
			// 获取函数名
			funcName := block.Name
			if funcName == "" {
				if name, ok := toolIDToName[block.ToolUseID]; ok {
					funcName = name
				} else {
					funcName = block.ToolUseID
				}
			}

			// 解析 content
			resultContent := parseToolResultContent(block.Content, block.IsError)

			part := GeminiPart{
				FunctionResponse: &GeminiFunctionResponse{
					Name: funcName,
					Response: map[string]any{
						"result": resultContent,
					},
					ID: block.ToolUseID,
				},
			}
			if isThinkingEnabled && lastThoughtSignature != nil && isValidThoughtSignature(*lastThoughtSignature) {
				part.ThoughtSignature = *lastThoughtSignature
			}
			parts = append(parts, part)
		}
	}

	return parts, strippedThinking, nil
}

// parseToolResultContent 解析 tool_result 的 content
func parseToolResultContent(content json.RawMessage, isError bool) string {
	if len(content) == 0 {
		if isError {
			return "Tool execution failed with no output."
		}
		return "Command executed successfully."
	}

	// 尝试解析为字符串
	var str string
	if err := json.Unmarshal(content, &str); err == nil {
		if strings.TrimSpace(str) == "" {
			if isError {
				return "Tool execution failed with no output."
			}
			return "Command executed successfully."
		}
		return str
	}

	// 尝试解析为数组
	var arr []map[string]any
	if err := json.Unmarshal(content, &arr); err == nil {
		var texts []string
		for _, item := range arr {
			if text, ok := item["text"].(string); ok {
				texts = append(texts, text)
			}
		}
		result := strings.Join(texts, "\n")
		if strings.TrimSpace(result) == "" {
			if isError {
				return "Tool execution failed with no output."
			}
			return "Command executed successfully."
		}
		return result
	}

	// 返回原始 JSON
	return string(content)
}

// buildGenerationConfig 构建 generationConfig
const (
	defaultMaxOutputTokens    = 64000
	maxOutputTokensUpperBound = 65000
	maxOutputTokensClaude     = 64000
)

func maxOutputTokensLimit(model string) int {
	if strings.HasPrefix(model, "claude-") {
		return maxOutputTokensClaude
	}
	return maxOutputTokensUpperBound
}

func buildGenerationConfig(req *ClaudeRequest) *GeminiGenerationConfig {
	maxLimit := maxOutputTokensLimit(req.Model)
	config := &GeminiGenerationConfig{
		MaxOutputTokens: defaultMaxOutputTokens, // 默认最大输出
		StopSequences:   DefaultStopSequences,
	}

	// 如果请求中指定了 MaxTokens，使用请求值
	if req.MaxTokens > 0 {
		config.MaxOutputTokens = req.MaxTokens
	}

	// Thinking 配置
	if req.Thinking != nil && req.Thinking.Type == "enabled" {
		config.ThinkingConfig = &GeminiThinkingConfig{
			IncludeThoughts: true,
		}
		if req.Thinking.BudgetTokens > 0 {
			budget := req.Thinking.BudgetTokens
			// gemini-2.5-flash 上限 24576
			if strings.Contains(req.Model, "gemini-2.5-flash") && budget > 24576 {
				budget = 24576
			}
			config.ThinkingConfig.ThinkingBudget = budget
			if config.MaxOutputTokens < budget {
				bumped := budget + 8192
				if bumped > 65000 {
					bumped = 65000
				}
				config.MaxOutputTokens = bumped
			}
		}
	}

	if config.MaxOutputTokens > maxLimit {
		config.MaxOutputTokens = maxLimit
	}

	// 其他参数
	if req.Temperature != nil {
		config.Temperature = req.Temperature
	}
	if req.TopP != nil {
		config.TopP = req.TopP
	}
	if req.TopK != nil {
		config.TopK = req.TopK
	}

	return config
}

func hasWebSearchTool(tools []ClaudeTool) bool {
	for _, tool := range tools {
		if isWebSearchTool(tool) {
			return true
		}
	}
	return false
}

func isWebSearchTool(tool ClaudeTool) bool {
	if strings.HasPrefix(tool.Type, "web_search") || tool.Type == "google_search" {
		return true
	}

	name := strings.TrimSpace(tool.Name)
	switch name {
	case "web_search", "google_search", "web_search_20250305":
		return true
	default:
		return false
	}
}

// buildTools 构建 tools
func buildTools(tools []ClaudeTool) []GeminiToolDeclaration {
	if len(tools) == 0 {
		return nil
	}

	hasWebSearch := hasWebSearchTool(tools)

	// 普通工具
	var funcDecls []GeminiFunctionDecl
	for _, tool := range tools {
		if isWebSearchTool(tool) {
			continue
		}
		// 跳过无效工具名称
		if strings.TrimSpace(tool.Name) == "" {
			log.Printf("Warning: skipping tool with empty name")
			continue
		}

		var description string
		var inputSchema map[string]any

		// 检查是否为 custom 类型工具 (MCP)
		if tool.Type == "custom" {
			if tool.Custom == nil || tool.Custom.InputSchema == nil {
				log.Printf("[Warning] Skipping invalid custom tool '%s': missing custom spec or input_schema", tool.Name)
				continue
			}
			description = tool.Custom.Description
			inputSchema = tool.Custom.InputSchema

		} else {
			// 标准格式: 从顶层字段获取
			description = tool.Description
			inputSchema = tool.InputSchema
		}

		// 清理 JSON Schema
		// 1. 深度清理 [undefined] 值
		DeepCleanUndefined(inputSchema)
		// 2. 转换为符合 Gemini v1internal 的 schema
		params := CleanJSONSchema(inputSchema)
		// 为 nil schema 提供默认值
		if params == nil {
			params = map[string]any{
				"type":       "object", // lowercase type
				"properties": map[string]any{},
			}
		}

		funcDecls = append(funcDecls, GeminiFunctionDecl{
			Name:        tool.Name,
			Description: description,
			Parameters:  params,
		})
	}

	if len(funcDecls) == 0 {
		if !hasWebSearch {
			return nil
		}

		// Web Search 工具映射
		return []GeminiToolDeclaration{{
			GoogleSearch: &GeminiGoogleSearch{
				EnhancedContent: &GeminiEnhancedContent{
					ImageSearch: &GeminiImageSearch{
						MaxResultCount: 5,
					},
				},
			},
		}}
	}

	return []GeminiToolDeclaration{{
		FunctionDeclarations: funcDecls,
	}}
}
