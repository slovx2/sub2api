package service

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/tlsfingerprint"
	"github.com/Wei-Shaw/sub2api/internal/service/basispoints"
	"github.com/google/uuid"
)

// applyModelTraceCodexHeaders 仅构造探测身份，复用现有纯函数，不改变 Codex 业务链路。
func applyModelTraceCodexHeaders(req *http.Request, account *Account) {
	req.Host = "chatgpt.com"
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("OpenAI-Beta", "responses=experimental")
	canonical := resolveCodexOutboundIdentity("")
	req.Header.Set("Originator", canonical.originator)
	ua := strings.TrimSpace(account.GetOpenAIUserAgent())
	if ua == "" {
		ua = canonical.userAgent
	}
	req.Header.Set("User-Agent", ua)
	setOpenAIChatGPTAccountHeaders(req.Header, account)
	enforceCodexIdentityHeadersWithUA(req.Header, account.GetOpenAIUserAgent())
}

type modelTraceCaller interface {
	Call(context.Context, *Account, string, string, string) (ProbeReply, error)
}
type ProbeReply struct {
	Text          string
	Status        int
	UpstreamModel string
}

// 凭证错误无法通过重复挑战恢复，直接结束当前组合。
type modelTraceCredentialError string

func (e modelTraceCredentialError) Error() string { return string(e) }

// OpenAIProbeTransport 仅读取现有凭证并发送请求；不依赖凭证刷新或账号状态写入。
type OpenAIProbeTransport struct {
	upstream HTTPUpstream
	profiles *TLSFingerprintProfileService
}

func NewOpenAIProbeTransport(upstream HTTPUpstream, profiles *TLSFingerprintProfileService) *OpenAIProbeTransport {
	return &OpenAIProbeTransport{upstream: upstream, profiles: profiles}
}
func (p *OpenAIProbeTransport) Call(ctx context.Context, account *Account, protocol, model, prompt string) (ProbeReply, error) {
	reply := ProbeReply{}
	if err := ctx.Err(); err != nil {
		return reply, err
	}
	if !ModelTraceEligible(account) {
		return reply, errors.New("账号不可探测")
	}
	// 只读当前凭证；刷新与凭证缓存完全由已有上游实现负责。
	token := strings.TrimSpace(account.GetOpenAIAccessToken())
	if token == "" {
		return reply, modelTraceCredentialError("缺少探测凭证")
	}
	if expires := account.GetCredentialAsTime("expires_at"); expires != nil && !time.Now().Before(*expires) {
		return reply, modelTraceCredentialError("探测凭证已过期")
	}
	var err error
	mapped := account.GetMappedModel(model)
	payload := map[string]any{"model": mapped, "stream": true, "store": false, "input": []any{map[string]any{"role": "user", "content": []any{map[string]any{"type": "input_text", "text": prompt}}}}, "reasoning": map[string]any{"effort": "low"}}
	var req *http.Request
	var bridge *basispoints.Bridge
	if protocol == "bps" {
		raw, _ := json.Marshal(payload)
		body, b, prepareErr := basispoints.Prepare(raw, "modeltrace:"+uuid.NewString(), nil)
		if prepareErr != nil {
			return reply, errors.New("BPS 请求构造失败")
		}
		bridge = b
		id := excelBPSAccountID(account, token)
		if id == "" {
			return reply, modelTraceCredentialError("缺少 ChatGPT 账号标识")
		}
		requestCtx := WithHTTPUpstreamRedirectsDisabled(WithHTTPUpstreamProfile(ctx, HTTPUpstreamProfileLongStream))
		req, err = newExcelBPSRequest(requestCtx, body, token, id)
	} else if protocol == "codex" {
		mapped = normalizeOpenAIModelForUpstream(account, mapped)
		payload["model"] = mapped
		payload["instructions"] = "You are Codex, a coding agent based on GPT-5"
		if mapped == "gpt-6-astra" {
			payload["instructions"] = "You are Codex, an agent based on GPT-6"
		}
		payload["service_tier"] = "priority"
		session := uuid.NewString()
		payload["prompt_cache_key"] = session
		body, _ := json.Marshal(payload)
		req, err = http.NewRequestWithContext(WithHTTPUpstreamProfile(ctx, HTTPUpstreamProfileOpenAI), http.MethodPost, chatgptCodexAPIURL, bytes.NewReader(body))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+token)
			applyModelTraceCodexHeaders(req, account)
			req.Header.Set("session_id", session)
			req.Header.Set("session-id", session)
			req.Header.Set("thread-id", session)
			account.ApplyHeaderOverrides(req.Header)
		}
	} else {
		return reply, errors.New("不支持的探测协议")
	}
	reply.UpstreamModel = mapped
	if err != nil {
		return reply, errors.New("探测请求构造失败")
	}
	proxy := ""
	if account.Proxy != nil {
		proxy = account.Proxy.URL()
	}
	var profile *tlsfingerprint.Profile
	if p.profiles != nil && protocol == "codex" {
		profile = p.profiles.ResolveTLSProfile(account)
	}
	var resp *http.Response
	if protocol == "bps" {
		resp, err = p.upstream.Do(req, proxy, account.ID, account.Concurrency)
	} else {
		resp, err = p.upstream.DoWithTLS(req, proxy, account.ID, account.Concurrency, profile)
	}
	if err != nil {
		return reply, errors.New("探测网络请求失败")
	}
	defer resp.Body.Close()
	reply.Status = resp.StatusCode
	if resp.StatusCode != http.StatusOK {
		return reply, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var stream io.Reader = resp.Body
	if bridge != nil {
		converted := bridge.Stream(resp.Body)
		defer converted.Close()
		stream = converted
	}
	reply.Text, err = readProbeResponse(stream)
	return reply, err
}

func readProbeResponse(reader io.Reader) (string, error) {
	scanner := bufio.NewScanner(io.LimitReader(reader, 2<<20))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	var text strings.Builder
	completed := false
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if data == "[DONE]" {
			continue
		}
		var event struct {
			Type     string `json:"type"`
			Delta    string `json:"delta"`
			Response struct {
				Output []struct {
					Content []struct {
						Type string `json:"type"`
						Text string `json:"text"`
					} `json:"content"`
				} `json:"output"`
			} `json:"response"`
		}
		if json.Unmarshal([]byte(data), &event) != nil {
			continue
		}
		switch event.Type {
		case "response.output_text.delta":
			text.WriteString(event.Delta)
		case "response.completed":
			completed = true
			if text.Len() == 0 {
				for _, o := range event.Response.Output {
					for _, c := range o.Content {
						if c.Type == "output_text" {
							text.WriteString(c.Text)
						}
					}
				}
			}
		case "error", "response.failed", "response.incomplete":
			return "", errors.New("上游未完成探测响应")
		}
		if text.Len() > 256<<10 {
			return "", errors.New("探测响应过长")
		}
	}
	if err := scanner.Err(); err != nil {
		return "", errors.New("探测响应读取中断")
	}
	if !completed {
		return "", errors.New("探测响应未完成")
	}
	return text.String(), nil
}
