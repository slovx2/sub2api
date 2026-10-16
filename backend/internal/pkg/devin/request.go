package devin

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/tidwall/gjson"
)

// RequestOptions 携带 chat 投影里丢失的入站信息。
type RequestOptions struct {
	// CustomTools 为入站 custom 工具名到 format 原文的映射。chat 投影把它们降级成
	// {"input"} 函数，这里按名字还原为 Devin 原生自由文本工具。
	CustomTools map[string]json.RawMessage
	// ModelLevels 返回账号同步到的模型思考档位，用于解析内置目录之外的新模型（如 gpt-6-1-sol）。
	ModelLevels func(model string) []string
}

// NewChatRequest 使用 CPA 的字段编号和客户端元数据构建原生 Devin 请求。
// sessionID 由调用方按用户及账号隔离；不会把客户端凭证传给上游。
func NewChatRequest(ctx context.Context, baseURL, token, sessionID string, body []byte, opts RequestOptions) (*http.Request, error) {
	if !json.Valid(body) {
		return nil, fmt.Errorf("invalid chat JSON")
	}
	root := gjson.ParseBytes(body)
	if root.Get("model").String() == "" || !root.Get("messages").IsArray() {
		return nil, fmt.Errorf("model and messages are required")
	}
	if n := root.Get("n"); n.Exists() && n.Int() != 1 {
		return nil, fmt.Errorf("Devin only supports n=1")
	}
	if choice := root.Get("tool_choice"); choice.Exists() && choice.String() != "auto" && choice.String() != "none" {
		return nil, fmt.Errorf("Devin does not support forced tool_choice")
	}
	structured, err := structuredOutputTool(root.Get("response_format"))
	if err != nil {
		return nil, err
	}
	var system []string
	var prompts []DevinPrompt
	pending := map[string]bool{}
	for _, msg := range root.Get("messages").Array() {
		content, images, err := chatContent(msg.Get("content"))
		if err != nil {
			return nil, err
		}
		p := DevinPrompt{MessageID: uuid.NewString(), Content: content, Images: images}
		switch msg.Get("role").String() {
		case "system", "developer":
			if len(images) > 0 {
				return nil, fmt.Errorf("Devin system messages cannot contain images")
			}
			system = append(system, content)
			continue
		case "user":
			p.Source = 1
		case "assistant":
			p.Source = 2
		case "tool":
			p.Source = 4
			p.ToolCallID = msg.Get("tool_call_id").String()
			if !pending[p.ToolCallID] {
				return nil, fmt.Errorf("tool result has no matching tool call")
			}
			delete(pending, p.ToolCallID)
		default:
			return nil, fmt.Errorf("unsupported Devin message role")
		}
		p.Thinking = msg.Get("reasoning_content").String()
		if p.Thinking == "" {
			p.Thinking = msg.Get("reasoning").String()
		}
		if signature := msg.Get("reasoning_signature").String(); signature != "" {
			p.Signature, p.SignatureType, err = unpackSignature(signature)
			if err != nil {
				return nil, fmt.Errorf("invalid reasoning signature")
			}
		}
		for _, tc := range msg.Get("tool_calls").Array() {
			if p.Source != 2 || tc.Get("type").String() != "function" {
				return nil, fmt.Errorf("Devin requires assistant function tool calls")
			}
			call := DevinToolCall{ID: tc.Get("id").String(), Name: tc.Get("function.name").String(), Arguments: tc.Get("function.arguments").String()}
			if call.ID == "" || call.Name == "" {
				return nil, fmt.Errorf("tool call id and name are required")
			}
			if _, custom := opts.CustomTools[call.Name]; custom {
				call.Custom = true
				call.Arguments = gjson.Get(call.Arguments, "input").String()
			}
			pending[call.ID] = true
			p.ToolCalls = append(p.ToolCalls, call)
		}
		prompts = append(prompts, p)
	}
	if len(prompts) == 0 {
		return nil, fmt.Errorf("Devin requires a conversation message")
	}
	var tools []DevinTool
	if root.Get("tool_choice").String() != "none" {
		for _, tool := range root.Get("tools").Array() {
			if tool.Get("type").String() != "function" {
				return nil, fmt.Errorf("Devin requires function tools")
			}
			fn := tool.Get("function")
			if fn.Get("name").String() == "" {
				return nil, fmt.Errorf("tool name is required")
			}
			description := rewriteCodexExecCommandDescription(fn.Get("description").String())
			if format, custom := opts.CustomTools[fn.Get("name").String()]; custom {
				tools = append(tools, customDevinTool(fn.Get("name").String(), description, format))
				continue
			}
			params := fn.Get("parameters").Raw
			if params == "" {
				params = `{"type":"object","properties":{}}`
			}
			tools = append(tools, DevinTool{Name: fn.Get("name").String(), Description: description, Parameters: []byte(params)})
		}
	}
	if structured != nil {
		for _, tool := range tools {
			if tool.Name == StructuredOutputToolName {
				return nil, fmt.Errorf("tool name %q is reserved for Devin structured output", StructuredOutputToolName)
			}
		}
		tools = append(tools, *structured)
		system = append(system, structuredOutputInstruction)
	}
	model := root.Get("model").String()
	uid := ResolveDevinChatModelUID(model, root.Get("reasoning_effort").String(), 0, opts.ModelLevels)
	maxTokens := int(root.Get("max_completion_tokens").Int())
	if maxTokens <= 0 {
		maxTokens = int(root.Get("max_tokens").Int())
	}
	if info := LookupModel(strings.ReplaceAll(model, ".", "-")); info != nil && info.MaxCompletionTokens > 0 && (maxTokens <= 0 || maxTokens > info.MaxCompletionTokens) {
		maxTokens = info.MaxCompletionTokens
	}
	var temperature *float64
	if t := root.Get("temperature"); t.Exists() {
		value := t.Float()
		temperature = &value
	}
	RestoreDevinToolCallIDs(prompts)
	payload := BuildDevinGetChatMessageRequest(token, "", uid, strings.Join(system, "\n"), prompts, tools, temperature, maxTokens, sessionID, sessionID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(baseURL, "/")+DevinChatPath, bytes.NewReader(WrapConnectEnvelope(payload)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Basic "+token+"-"+token)
	req.Header.Set("Content-Type", "application/connect+proto")
	req.Header.Set("Connect-Protocol-Version", "1")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Sentry-Trace", GenerateDevinSentryTrace())
	req.Header["User-Agent"] = []string{""}
	return req, nil
}

// customDevinTool 按 Responses custom 工具的 format 声明自由文本工具；text 或缺省格式只带 custom 标记。
func customDevinTool(name, description string, format json.RawMessage) DevinTool {
	tool := DevinTool{Name: name, Description: description, Custom: true}
	if gjson.GetBytes(format, "type").String() == "grammar" {
		tool.Grammar = gjson.GetBytes(format, "definition").String()
		tool.GrammarSyntax = gjson.GetBytes(format, "syntax").String()
	}
	return tool
}

func chatContent(content gjson.Result) (string, []DevinImage, error) {
	if content.Type == gjson.String {
		return content.String(), nil, nil
	}
	if !content.Exists() || content.Type == gjson.Null {
		return "", nil, nil
	}
	if !content.IsArray() {
		return "", nil, fmt.Errorf("invalid message content")
	}
	var text []string
	var images []DevinImage
	for _, part := range content.Array() {
		switch part.Get("type").String() {
		case "text":
			text = append(text, part.Get("text").String())
		case "image_url":
			data := part.Get("image_url.url").String()
			header, encoded, ok := strings.Cut(data, ",")
			if !ok || !strings.HasPrefix(header, "data:image/") || !strings.HasSuffix(header, ";base64") {
				return "", nil, fmt.Errorf("Devin images require base64 data URLs")
			}
			if _, err := base64.StdEncoding.DecodeString(encoded); err != nil {
				return "", nil, fmt.Errorf("invalid base64 image")
			}
			images = append(images, DevinImage{Base64Data: encoded, MimeType: strings.TrimSuffix(strings.TrimPrefix(header, "data:"), ";base64")})
		default:
			return "", nil, fmt.Errorf("unsupported Devin content type: %s", part.Get("type").String())
		}
	}
	return strings.Join(text, "\n"), images, nil
}
