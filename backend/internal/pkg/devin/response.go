package devin

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
)

type UpstreamError struct {
	Status  int
	Message string
}

func (e *UpstreamError) Error() string { return e.Message }

// chatDecoder 按 CPA 的帧顺序合并工具增量及累计用量，不把截断流视为成功。
type chatDecoder struct {
	body           io.ReadCloser
	id, model      string
	created        int64
	usage          DevinUsage
	hasUsage, done bool
	stop           uint64
	toolIDs        map[string]int
	toolNames      map[int]string
	toolArguments  map[int]*UTF8SplitBuffer
	lastTool       int
	text, thinking UTF8SplitBuffer
	readBytes      int
	signature      bytes.Buffer
	signatureType  string
	thinkingSeen   bool
	queued         []map[string]any
}

func (d *chatDecoder) next() (map[string]any, error) {
	if d.done {
		if len(d.queued) > 0 {
			chunk := d.queued[0]
			d.queued = d.queued[1:]
			return chunk, nil
		}
		return nil, io.EOF
	}
	for {
		flag, payload, err := ReadConnectFrame(d.body)
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("Devin stream ended without terminal frame")
		}
		if err != nil {
			return nil, err
		}
		d.readBytes += len(payload)
		if d.readBytes > 64<<20 {
			return nil, fmt.Errorf("Devin response exceeds 64 MiB")
		}
		if flag&ConnectFlagEndStream != 0 {
			if !json.Valid(payload) || len(bytes.TrimSpace(payload)) == 0 || bytes.TrimSpace(payload)[0] != '{' {
				return nil, fmt.Errorf("invalid Devin terminal frame")
			}
			status, err := ParseDevinTrailerError(payload)
			if err != nil {
				return nil, &UpstreamError{status, err.Error()}
			}
			if !d.hasUsage {
				return nil, fmt.Errorf("Devin terminal frame is missing usage")
			}
			if len(d.text.remainder) > 0 || len(d.thinking.remainder) > 0 {
				return nil, fmt.Errorf("incomplete Devin UTF-8 output")
			}
			for index, arguments := range d.toolArguments {
				if len(arguments.remainder) > 0 || d.toolNames[index] == "" {
					return nil, fmt.Errorf("incomplete Devin tool output")
				}
			}
			d.done = true
			reason := "stop"
			if len(d.toolIDs) > 0 || d.stop == 10 {
				reason = "tool_calls"
			}
			switch d.stop {
			case 1, 3:
				reason = "length"
			case 11:
				reason = "content_filter"
			}
			chunk := d.chunk(map[string]any{}, reason)
			input := d.usage.PromptTokens + d.usage.CachedTokens
			chunk["usage"] = map[string]any{"prompt_tokens": input, "completion_tokens": d.usage.CompletionTokens, "total_tokens": input + d.usage.CompletionTokens,
				"prompt_tokens_details": map[string]any{"cached_tokens": d.usage.CachedTokens, "cache_creation_tokens": d.usage.CacheWriteTokens}}
			d.queued = append(d.queued, chunk)
			if d.signature.Len() > 0 {
				return d.chunk(map[string]any{"reasoning_signature": packSignature(d.signature.Bytes(), d.signatureType)}, nil), nil
			}
			return d.next()
		}
		frame, err := ParseDevinFrame(payload)
		if err != nil {
			return nil, fmt.Errorf("invalid Devin response: %w", err)
		}
		if len(frame.DeltaSignature) > 0 {
			d.signature.Write(frame.DeltaSignature)
			d.thinkingSeen = true
		}
		if frame.DeltaSignatureType != "" {
			d.signatureType = frame.DeltaSignatureType
		}
		if frame.StopReason != 0 {
			d.stop = frame.StopReason
		}
		if u := frame.Usage; u != nil {
			d.hasUsage = true
			if u.StatusCode >= 400 {
				return nil, &UpstreamError{int(u.StatusCode), "Devin upstream rejected request"}
			}
			if u.PromptTokens > 0 {
				d.usage.PromptTokens = u.PromptTokens
			}
			if u.CompletionTokens > 0 {
				d.usage.CompletionTokens = u.CompletionTokens
			}
			if u.CachedTokens > 0 {
				d.usage.CachedTokens = u.CachedTokens
			}
			if u.CacheWriteTokens > 0 {
				d.usage.CacheWriteTokens = u.CacheWriteTokens
			}
		}
		if in, out, cached, ok := ParseDevinResponseDimensionGroups(frame.ResponseDimensionGroups...); ok {
			d.hasUsage = true
			if d.usage.PromptTokens == 0 {
				d.usage.PromptTokens = in
			}
			if d.usage.CompletionTokens == 0 {
				d.usage.CompletionTokens = out
			}
			if d.usage.CachedTokens == 0 {
				d.usage.CachedTokens = cached
			}
		}
		delta := map[string]any{}
		if text := d.text.Feed([]byte(frame.ContentText)); text != "" {
			delta["content"] = text
		}
		if text := d.thinking.Feed([]byte(frame.ThinkingText)); text != "" {
			delta["reasoning_content"] = text
			d.thinkingSeen = true
		}
		var calls []map[string]any
		for _, tc := range frame.ToolCallDeltas {
			index, exists := d.toolIDs[tc.ID]
			if tc.ID == "" && d.lastTool >= 0 {
				index = d.lastTool
				exists = true
			}
			first := !exists
			if first {
				if tc.ID == "" {
					return nil, fmt.Errorf("Devin tool delta is missing initial id")
				}
				if len(d.toolIDs) >= 128 {
					return nil, fmt.Errorf("too many Devin tool calls")
				}
				index = len(d.toolIDs)
				d.toolIDs[tc.ID] = index
			}
			d.lastTool = index
			args := tc.Arguments
			if args == "" {
				args = tc.InvalidJSONStr
			}
			if d.toolArguments[index] == nil {
				d.toolArguments[index] = &UTF8SplitBuffer{}
			}
			args = d.toolArguments[index].Feed([]byte(args))
			fn := map[string]any{"arguments": args}
			if tc.Name != "" {
				if previous := d.toolNames[index]; previous == "" {
					fn["name"] = tc.Name
					d.toolNames[index] = tc.Name
				} else if previous != tc.Name {
					return nil, fmt.Errorf("Devin tool name changed mid-call")
				}
			}
			call := map[string]any{"index": index, "function": fn}
			if first {
				call["id"] = EncodeDevinToolCallID(tc.ID)
				call["type"] = "function"
			}
			calls = append(calls, call)
		}
		if len(calls) > 0 {
			delta["tool_calls"] = calls
		}
		if len(delta) > 0 {
			// CPA 在思考后暂存正文/工具，等晚到或分片签名完整后再关闭思考块。
			if d.thinkingSeen {
				thinking, hasThinking := delta["reasoning_content"]
				delete(delta, "reasoning_content")
				if len(delta) > 0 {
					if len(d.queued) >= 65536 {
						return nil, fmt.Errorf("too many pending Devin output chunks")
					}
					d.queued = append(d.queued, d.chunk(delta, nil))
				}
				if hasThinking {
					return d.chunk(map[string]any{"reasoning_content": thinking}, nil), nil
				}
				continue
			}
			return d.chunk(delta, nil), nil
		}
	}
}

func (d *chatDecoder) chunk(delta map[string]any, finish any) map[string]any {
	return map[string]any{"id": d.id, "object": "chat.completion.chunk", "created": d.created, "model": d.model,
		"choices": []any{map[string]any{"index": 0, "delta": delta, "finish_reason": finish}}}
}

// ConvertChatResponse 在首个有效输出前检查 Connect 错误，使账号切换仍然可用。
// 使用按需读取的适配器，不为每个请求创建常驻缓冲 goroutine。
func ConvertChatResponse(resp *http.Response, model string, stream bool) (*http.Response, error) {
	if resp.StatusCode >= 400 {
		return resp, nil
	}
	d := &chatDecoder{body: resp.Body, id: "chatcmpl-" + uuid.NewString(), model: model, created: time.Now().Unix(), toolIDs: map[string]int{}, toolNames: map[int]string{}, toolArguments: map[int]*UTF8SplitBuffer{}, lastTool: -1}
	first, err := d.next()
	if err != nil {
		return convertedError(resp, err)
	}
	out := new(http.Response)
	*out = *resp
	out.Header = resp.Header.Clone()
	out.Header.Del("Content-Length")
	out.Header.Del("Content-Encoding")
	out.ContentLength = -1
	if stream {
		out.Header.Set("Content-Type", "text/event-stream")
		r := &chatStream{decoder: d}
		r.enqueue(first)
		out.Body = r
		return out, nil
	}
	body, err := bufferChat(d, first)
	_ = resp.Body.Close()
	if err != nil {
		return convertedError(resp, err)
	}
	out.Header.Set("Content-Type", "application/json")
	out.Body = io.NopCloser(bytes.NewReader(body))
	return out, nil
}

func convertedError(resp *http.Response, err error) (*http.Response, error) {
	_ = resp.Body.Close()
	status := http.StatusBadGateway
	var upstream *UpstreamError
	if errors.As(err, &upstream) {
		status = upstream.Status
	}
	body, _ := json.Marshal(map[string]any{"error": map[string]string{"type": "upstream_error", "message": err.Error()}})
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(body))}, nil
}

type chatStream struct {
	decoder *chatDecoder
	pending bytes.Buffer
	ended   bool
}

func (s *chatStream) enqueue(chunk map[string]any) {
	body, _ := json.Marshal(chunk)
	s.pending.WriteString("data: ")
	s.pending.Write(body)
	s.pending.WriteString("\n\n")
}
func (s *chatStream) Read(p []byte) (int, error) {
	if s.pending.Len() > 0 {
		return s.pending.Read(p)
	}
	if s.ended {
		return 0, io.EOF
	}
	chunk, err := s.decoder.next()
	if errors.Is(err, io.EOF) {
		s.ended = true
		s.pending.WriteString("data: [DONE]\n\n")
	} else if err != nil {
		return 0, err
	} else {
		s.enqueue(chunk)
	}
	return s.pending.Read(p)
}
func (s *chatStream) Close() error { return s.decoder.body.Close() }

func bufferChat(d *chatDecoder, first map[string]any) ([]byte, error) {
	var content, reasoning bytes.Buffer
	var signature string
	calls := []map[string]any{}
	var usage, finish any
	for chunk := first; chunk != nil; {
		choice := chunk["choices"].([]any)[0].(map[string]any)
		delta := choice["delta"].(map[string]any)
		if value, ok := delta["reasoning_signature"].(string); ok {
			signature = value
		}
		if value, ok := delta["content"].(string); ok {
			content.WriteString(value)
		}
		if value, ok := delta["reasoning_content"].(string); ok {
			reasoning.WriteString(value)
		}
		if list, ok := delta["tool_calls"].([]map[string]any); ok {
			for _, tc := range list {
				idx := tc["index"].(int)
				for len(calls) <= idx {
					calls = append(calls, map[string]any{"type": "function", "function": map[string]any{"name": "", "arguments": ""}})
				}
				if id, ok := tc["id"]; ok {
					calls[idx]["id"] = id
				}
				fn := tc["function"].(map[string]any)
				stored := calls[idx]["function"].(map[string]any)
				if name, ok := fn["name"]; ok {
					stored["name"] = name
				}
				stored["arguments"] = stored["arguments"].(string) + fn["arguments"].(string)
			}
		}
		if chunk["usage"] != nil {
			usage = chunk["usage"]
			finish = choice["finish_reason"]
		}
		var err error
		chunk, err = d.next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	message := map[string]any{"role": "assistant", "content": content.String()}
	if signature != "" {
		message["reasoning_signature"] = signature
	}
	if reasoning.Len() > 0 {
		message["reasoning_content"] = reasoning.String()
	}
	if len(calls) > 0 {
		message["tool_calls"] = calls
	}
	return json.Marshal(map[string]any{"id": d.id, "object": "chat.completion", "created": d.created, "model": d.model, "usage": usage,
		"choices": []any{map[string]any{"index": 0, "message": message, "finish_reason": finish}}})
}
