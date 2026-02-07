package service

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// 用于在 gin.Context 中暂存上游错误信息，供 Ops 错误日志落库使用。
// 这些 key 由 gateway service 写入，由 handler/ops_error_logger.go 读取。
const (
	OpsUpstreamStatusCodeKey   = "ops_upstream_status_code"
	OpsUpstreamErrorMessageKey = "ops_upstream_error_message"
	OpsUpstreamErrorDetailKey  = "ops_upstream_error_detail"
	OpsUpstreamErrorsKey       = "ops_upstream_errors"

	// 用于记录当前上游请求 URL（最佳努力）。
	// 会在落库前做截断。
	OpsUpstreamRequestURLKey = "ops_upstream_request_url"

	// 用于记录当前上游请求体（最佳努力），便于 Ops 重试某一次具体的上游请求。
	// 会在落库前做脱敏和截断。
	OpsUpstreamRequestBodyKey = "ops_upstream_request_body"
)

func setOpsUpstreamError(c *gin.Context, upstreamStatusCode int, upstreamMessage, upstreamDetail string) {
	if c == nil {
		return
	}
	if upstreamStatusCode > 0 {
		c.Set(OpsUpstreamStatusCodeKey, upstreamStatusCode)
	}
	if msg := strings.TrimSpace(upstreamMessage); msg != "" {
		c.Set(OpsUpstreamErrorMessageKey, msg)
	}
	if detail := strings.TrimSpace(upstreamDetail); detail != "" {
		c.Set(OpsUpstreamErrorDetailKey, detail)
	}
}

// OpsUpstreamErrorEvent describes one upstream error attempt during a single gateway request.
// It is stored in ops_error_logs.upstream_errors as a JSON array.
type OpsUpstreamErrorEvent struct {
	AtUnixMs int64 `json:"at_unix_ms,omitempty"`

	// Context
	Platform    string `json:"platform,omitempty"`
	AccountID   int64  `json:"account_id,omitempty"`
	AccountName string `json:"account_name,omitempty"`

	// Outcome
	UpstreamStatusCode int    `json:"upstream_status_code,omitempty"`
	UpstreamRequestID  string `json:"upstream_request_id,omitempty"`

	// Best-effort upstream request capture (sanitized+trimmed).
	// Required for retrying a specific upstream attempt.
	UpstreamRequestURL  string `json:"upstream_request_url,omitempty"`
	UpstreamRequestBody string `json:"upstream_request_body,omitempty"`

	// Best-effort upstream response capture (sanitized+trimmed).
	UpstreamResponseBody string `json:"upstream_response_body,omitempty"`

	// Kind: http_error | request_error | retry_exhausted | failover
	Kind string `json:"kind,omitempty"`

	Message string `json:"message,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

func appendOpsUpstreamError(c *gin.Context, ev OpsUpstreamErrorEvent) {
	if c == nil {
		return
	}
	if ev.AtUnixMs <= 0 {
		ev.AtUnixMs = time.Now().UnixMilli()
	}
	ev.Platform = strings.TrimSpace(ev.Platform)
	ev.UpstreamRequestID = strings.TrimSpace(ev.UpstreamRequestID)
	ev.UpstreamRequestURL = strings.TrimSpace(ev.UpstreamRequestURL)
	ev.UpstreamRequestBody = strings.TrimSpace(ev.UpstreamRequestBody)
	ev.UpstreamResponseBody = strings.TrimSpace(ev.UpstreamResponseBody)
	ev.Kind = strings.TrimSpace(ev.Kind)
	ev.Message = strings.TrimSpace(ev.Message)
	ev.Detail = strings.TrimSpace(ev.Detail)
	if ev.Message != "" {
		ev.Message = sanitizeUpstreamErrorMessage(ev.Message)
	}

	// If the caller didn't explicitly pass upstream request body but the gateway
	// stored it on the context, attach it so ops can retry this specific attempt.
	if ev.UpstreamRequestURL == "" {
		if v, ok := c.Get(OpsUpstreamRequestURLKey); ok {
			if s, ok := v.(string); ok {
				ev.UpstreamRequestURL = strings.TrimSpace(s)
			}
		}
	}
	if ev.UpstreamRequestBody == "" {
		if v, ok := c.Get(OpsUpstreamRequestBodyKey); ok {
			if s, ok := v.(string); ok {
				ev.UpstreamRequestBody = strings.TrimSpace(s)
			}
		}
	}

	var existing []*OpsUpstreamErrorEvent
	if v, ok := c.Get(OpsUpstreamErrorsKey); ok {
		if arr, ok := v.([]*OpsUpstreamErrorEvent); ok {
			existing = arr
		}
	}

	evCopy := ev
	existing = append(existing, &evCopy)
	c.Set(OpsUpstreamErrorsKey, existing)
}

func marshalOpsUpstreamErrors(events []*OpsUpstreamErrorEvent) *string {
	if len(events) == 0 {
		return nil
	}
	// Ensure we always store a valid JSON value.
	raw, err := json.Marshal(events)
	if err != nil || len(raw) == 0 {
		return nil
	}
	s := string(raw)
	return &s
}

func ParseOpsUpstreamErrors(raw string) ([]*OpsUpstreamErrorEvent, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return []*OpsUpstreamErrorEvent{}, nil
	}
	var out []*OpsUpstreamErrorEvent
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, err
	}
	return out, nil
}
