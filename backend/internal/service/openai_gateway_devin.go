package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/pkg/apicompat"
	"github.com/Wei-Shaw/sub2api/internal/pkg/devin"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/tidwall/gjson"
)

func rememberDevinRequest(c *gin.Context, account *Account, body []byte) {
	if account.IsDevin() && c != nil {
		c.Set("devin_original_body", string(body))
	}
}

const devinCustomToolsContextKey = "devin_custom_tools"

// rememberDevinCustomTools 记下入站 custom 工具的 format；chat 投影会把它们降级成函数，
// Devin 出站时据此还原为原生自由文本工具。
func rememberDevinCustomTools(c *gin.Context, account *Account, tools []apicompat.ResponsesTool) {
	if account.IsDevin() && c != nil {
		c.Set(devinCustomToolsContextKey, apicompat.CustomToolFormats(tools))
	}
}

func devinRequestOptions(c *gin.Context, account *Account) devin.RequestOptions {
	opts := devin.RequestOptions{ModelLevels: devinAccountModelLevels(account)}
	if c != nil {
		if formats, ok := c.Get(devinCustomToolsContextKey); ok {
			opts.CustomTools, _ = formats.(map[string]json.RawMessage)
		}
	}
	return opts
}

// 转换前检查服务端工具，避免通用 CC 转换器丢弃 Devin 无法执行的声明。
func validateDevinClientTools(c *gin.Context, account *Account, body []byte, anthropic bool) error {
	if !account.IsDevin() {
		return nil
	}
	var check func(gjson.Result) error
	check = func(tool gjson.Result) error {
		kind := tool.Get("type").String()
		switch kind {
		case "function", "custom", "tool_search":
			return nil
		case "namespace":
			for _, child := range tool.Get("tools").Array() {
				if err := check(child); err != nil {
					return err
				}
			}
			return nil
		case "":
			if tool.Get("name").String() != "" {
				return nil
			}
		}
		return fmt.Errorf("Devin does not support server-side tool type %q", kind)
	}
	root := gjson.ParseBytes(body)
	tools := root.Get("tools").Array()
	for _, item := range root.Get("input").Array() {
		if item.Get("type").String() == "additional_tools" {
			tools = append(tools, item.Get("tools").Array()...)
		}
	}
	for _, tool := range tools {
		if err := check(tool); err != nil {
			if anthropic {
				c.JSON(http.StatusBadRequest, gin.H{"type": "error", "error": gin.H{"type": "invalid_request_error", "message": err.Error()}})
			} else {
				writeOpenAIResponsesFallbackError(c, http.StatusBadRequest, "invalid_request_error", err.Error())
			}
			return err
		}
	}
	return nil
}

func devinSessionID(c *gin.Context, account *Account, body []byte) string {
	original := []byte(c.GetString("devin_original_body"))
	if len(original) == 0 {
		original = body
	}
	root := gjson.ParseBytes(original)
	seed := firstNonEmpty(c.GetHeader("session_id"), c.GetHeader("conversation_id"), root.Get("prompt_cache_key").String(), root.Get("session_id").String(), extractClaudeCodeSessionID(c, original))
	if seed == "" {
		// 没有显式会话标识时，与 CPA 一样从会话起点派生；账号和租户始终隔离。
		for _, message := range gjson.GetBytes(body, "messages").Array() {
			if message.Get("role").String() == "user" {
				seed = message.Raw
				break
			}
		}
		if seed == "" {
			seed = uuid.NewString()
		}
	}
	return uuid.NewSHA1(uuid.NameSpaceURL, []byte(fmt.Sprintf("devin:%d:%d:%s", account.ID, getAPIKeyIDFromContext(c), seed))).String()
}

func (s *OpenAIGatewayService) sendDevinUpstreamRequest(ctx context.Context, c *gin.Context, account *Account, body []byte, stream bool) (*http.Response, error) {
	baseURL, err := s.validateUpstreamBaseURL(account.GetDevinBaseURL())
	if err != nil {
		return nil, err
	}
	token := account.GetDevinSessionToken()
	if token == "" {
		return nil, fmt.Errorf("Devin session_token is required")
	}
	upstreamCtx, releaseUpstreamCtx := detachUpstreamContext(ctx)
	req, err := devin.NewChatRequest(upstreamCtx, baseURL, token, devinSessionID(c, account, body), body, devinRequestOptions(c, account))
	releaseUpstreamCtx()
	if err != nil {
		payload, _ := json.Marshal(map[string]any{"error": map[string]string{"type": "invalid_request_error", "message": err.Error()}})
		return &http.Response{StatusCode: http.StatusBadRequest, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(payload))}, nil
	}
	SetActualOpenAIUpstreamEndpoint(c, devin.DevinChatPath)
	proxyURL := ""
	if account.ProxyID != nil && account.Proxy != nil {
		proxyURL = account.Proxy.URL()
	}
	resp, err := s.httpUpstream.Do(req, proxyURL, account.ID, account.Concurrency)
	if err != nil {
		return nil, s.handleOpenAIUpstreamTransportError(ctx, c, account, err, false)
	}
	return devin.ConvertChatResponse(resp, gjson.GetBytes(body, "model").String(), stream, gjson.GetBytes(body, "response_format.type").String() == "json_schema")
}

// devinAccountModelLevels 读取账号同步上游模型时保存的思考档位。
func devinAccountModelLevels(account *Account) func(string) []string {
	return func(model string) []string {
		metadata, ok := account.GetUpstreamModelMetadata(model)
		if !ok {
			return nil
		}
		return metadata.SupportedReasoningLevels
	}
}

// Devin 模型目录来自固定版本 CPA；账号授权范围由上游最终判定。
func devinModelsResponse() *OpenAIModelsResponse {
	body := devin.ModelsJSON()
	return &OpenAIModelsResponse{Body: body, ETag: codexModelsManifestBodyETag(body)}
}

func validateDevinCredentials(accountType string, credentials map[string]any) error {
	if accountType != AccountTypeOAuth {
		return fmt.Errorf("Devin accounts require oauth credentials")
	}
	token, _ := credentials["session_token"].(string)
	token = strings.TrimSpace(token)
	if !strings.HasPrefix(token, "devin-session-token$") || len(token) <= len("devin-session-token$") {
		return fmt.Errorf("a valid Devin session token is required")
	}
	credentials["session_token"] = token
	return nil
}
