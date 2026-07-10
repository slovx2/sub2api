package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/logger"
	"github.com/Wei-Shaw/sub2api/internal/pkg/openai"
	openaiwsv2 "github.com/Wei-Shaw/sub2api/internal/service/openai_ws_v2"
	coderws "github.com/coder/websocket"
	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
	"go.uber.org/zap"
)

type openAIWSClientFrameConn struct {
	conn *coderws.Conn
}

type openAIWSPingFrameConn interface {
	Ping(ctx context.Context) error
}

// openAIWSPolicyEnforcingFrameConn wraps a client-side FrameConn and runs
// every client→upstream frame through the OpenAI Fast Policy. It is the
// passthrough-relay equivalent of the parseClientPayload integration in the
// ingress session path. filter returns:
//   - newPayload, nil, nil: forward the (possibly mutated) payload
//   - _, *OpenAIFastBlockedError, nil: block — the wrapper sends an error
//     event via onBlock and surfaces a transport-level error so the relay
//     stops reading from the client.
//   - _, _, err: a transport error other than block.
type openAIWSPolicyEnforcingFrameConn struct {
	inner   openaiwsv2.FrameConn
	filter  func(msgType coderws.MessageType, payload []byte) ([]byte, *OpenAIFastBlockedError, error)
	onBlock func(blocked *OpenAIFastBlockedError)
}

var _ openaiwsv2.FrameConn = (*openAIWSPolicyEnforcingFrameConn)(nil)

func (c *openAIWSPolicyEnforcingFrameConn) ReadFrame(ctx context.Context) (coderws.MessageType, []byte, error) {
	if c == nil || c.inner == nil {
		return coderws.MessageText, nil, errOpenAIWSConnClosed
	}
	msgType, payload, err := c.inner.ReadFrame(ctx)
	if err != nil {
		return msgType, payload, err
	}
	if c.filter == nil {
		return msgType, payload, nil
	}
	updated, blocked, filterErr := c.filter(msgType, payload)
	if filterErr != nil {
		return msgType, payload, filterErr
	}
	if blocked != nil {
		if c.onBlock != nil {
			c.onBlock(blocked)
		}
		return msgType, nil, NewOpenAIWSClientCloseError(coderws.StatusPolicyViolation, blocked.Message, blocked)
	}
	return msgType, updated, nil
}

func (c *openAIWSPolicyEnforcingFrameConn) WriteFrame(ctx context.Context, msgType coderws.MessageType, payload []byte) error {
	if c == nil || c.inner == nil {
		return errOpenAIWSConnClosed
	}
	return c.inner.WriteFrame(ctx, msgType, payload)
}

func (c *openAIWSPolicyEnforcingFrameConn) Close() error {
	if c == nil || c.inner == nil {
		return nil
	}
	return c.inner.Close()
}

func (s *OpenAIGatewayService) startOpenAIWSPassthroughUpstreamKeepalive(
	ctx context.Context,
	conn any,
	accountID int64,
) func() {
	pinger, ok := conn.(openAIWSPingFrameConn)
	if !ok || pinger == nil {
		return func() {}
	}
	interval := openAIWSPassthroughPingInterval
	if interval <= 0 {
		return func() {}
	}
	keepaliveCtx, cancel := context.WithCancel(ctx)
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-keepaliveCtx.Done():
				return
			case <-ticker.C:
				pingCtx, cancelPing := context.WithTimeout(keepaliveCtx, s.openAIWSWriteTimeout())
				err := pinger.Ping(pingCtx)
				cancelPing()
				if err != nil {
					logOpenAIWSV2Passthrough(
						"relay_upstream_keepalive_ping_failed account_id=%d interval_ms=%d err=%s",
						accountID,
						interval.Milliseconds(),
						truncateOpenAIWSLogValue(err.Error(), openAIWSLogValueMaxLen),
					)
					return
				}
				logOpenAIWSV2Passthrough(
					"relay_upstream_keepalive_ping_ok account_id=%d interval_ms=%d",
					accountID,
					interval.Milliseconds(),
				)
			}
		}
	}()
	return cancel
}

// openAIWSPassthroughPolicyModelForFrame returns the upstream-perspective
// model name that should be passed to evaluateOpenAIFastPolicy for a single
// passthrough WS frame. Mirrors the HTTP-side normalization
// (account.GetMappedModel + normalizeOpenAIModelForUpstream) so the WS path
// matches model whitelists identically.
func openAIWSPassthroughPolicyModelForFrame(account *Account, payload []byte) string {
	if account == nil || len(payload) == 0 {
		return ""
	}
	original := strings.TrimSpace(gjson.GetBytes(payload, "model").String())
	if original == "" {
		return ""
	}
	return normalizeOpenAIModelForUpstream(account, account.GetMappedModel(original))
}

// openAIWSPassthroughPolicyModelFromSessionFrame returns the upstream model
// derived from a session.update frame's session.model field. Returns "" when
// the frame is not a session.update event or carries no session.model. Used
// by the per-frame policy filter (client→upstream direction) to keep
// capturedSessionModel in sync with the session-level model the client may
// rotate mid-session.
//
// Realtime / Responses WS lets the client change the session model after
// the WS handshake via:
//
//	{"type":"session.update","session":{"model":"gpt-5.5", ...}}
//
// If we only capture the model from the very first frame, a client can ship
// gpt-4o on the first response.create (whitelisted as pass), then
// session.update to gpt-5.5, then send response.create without "model" so
// the per-frame resolver returns "" and the stale capturedSessionModel falls
// back to gpt-4o — defeating the gpt-5.5 fast-policy filter.
func openAIWSPassthroughPolicyModelFromSessionFrame(account *Account, payload []byte) string {
	if account == nil || len(payload) == 0 {
		return ""
	}
	frameType := strings.TrimSpace(gjson.GetBytes(payload, "type").String())
	if frameType != "session.update" {
		return ""
	}
	original := strings.TrimSpace(gjson.GetBytes(payload, "session.model").String())
	if original == "" {
		return ""
	}
	return normalizeOpenAIModelForUpstream(account, account.GetMappedModel(original))
}

type openAIWSPassthroughUsageMeta struct {
	serviceTier     atomic.Pointer[string]
	reasoningEffort atomic.Pointer[string]

	// 仅在 client->upstream filter goroutine 中读写；Load 侧通过上方原子指针同步。
	sessionRequestModel string
}

func newOpenAIWSPassthroughUsageMeta(initialRequestModel string, firstFrame []byte) *openAIWSPassthroughUsageMeta {
	meta := &openAIWSPassthroughUsageMeta{
		sessionRequestModel: strings.TrimSpace(initialRequestModel),
	}
	if meta.sessionRequestModel == "" {
		meta.sessionRequestModel = openAIWSPassthroughRequestModelForFrame(firstFrame)
	}
	return meta
}

func (m *openAIWSPassthroughUsageMeta) initFromFirstFrame(policyOutput []byte, mappedModel string) {
	if m == nil {
		return
	}
	m.serviceTier.Store(extractOpenAIServiceTierFromBody(policyOutput))
	m.reasoningEffort.Store(extractOpenAIReasoningEffortFromBody(policyOutput, mappedModel, m.sessionRequestModel))
}

func (m *openAIWSPassthroughUsageMeta) updateSessionRequestModel(payload []byte) {
	if m == nil {
		return
	}
	if model := openAIWSPassthroughRequestModelFromSessionFrame(payload); model != "" {
		m.sessionRequestModel = model
	}
}

func (m *openAIWSPassthroughUsageMeta) requestModelForFrame(payload []byte) string {
	if m == nil {
		return openAIWSPassthroughRequestModelForFrame(payload)
	}
	if model := openAIWSPassthroughRequestModelForFrame(payload); model != "" {
		return model
	}
	return m.sessionRequestModel
}

func (m *openAIWSPassthroughUsageMeta) updateFromResponseCreate(policyOutput []byte, mappedModel string, requestModelForFrame string) {
	if m == nil {
		return
	}
	m.serviceTier.Store(extractOpenAIServiceTierFromBody(policyOutput))
	m.reasoningEffort.Store(extractOpenAIReasoningEffortFromBody(policyOutput, mappedModel, requestModelForFrame))
}

func openAIWSPassthroughRequestModelForFrame(payload []byte) string {
	if len(payload) == 0 || strings.TrimSpace(gjson.GetBytes(payload, "type").String()) != "response.create" {
		return ""
	}
	return strings.TrimSpace(gjson.GetBytes(payload, "model").String())
}

func openAIWSPassthroughRequestModelFromSessionFrame(payload []byte) string {
	if len(payload) == 0 || strings.TrimSpace(gjson.GetBytes(payload, "type").String()) != "session.update" {
		return ""
	}
	return strings.TrimSpace(gjson.GetBytes(payload, "session.model").String())
}

func openAIWSPassthroughFrameInputSummary(payload []byte) string {
	if len(payload) == 0 {
		return "-"
	}
	input := gjson.GetBytes(payload, "input")
	if !input.Exists() || strings.TrimSpace(input.Raw) == "" {
		return "-"
	}
	var decoded any
	if err := json.Unmarshal([]byte(input.Raw), &decoded); err != nil {
		return "parse_error"
	}
	return summarizeOpenAIWSInput(decoded)
}

func openAIWSPassthroughPayloadBoolForLog(payload []byte, key string) string {
	value := gjson.GetBytes(payload, key)
	if !value.Exists() {
		return "-"
	}
	if value.Type != gjson.True && value.Type != gjson.False {
		return "non_bool"
	}
	if value.Bool() {
		return "true"
	}
	return "false"
}

func normalizeOpenAIWSLogEnum(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "-"
	}
	return strings.Join(strings.Fields(trimmed), "_")
}

func logOpenAIWSV2PassthroughFrame(prefix string, accountID int64, turn int, payload []byte) {
	eventType := strings.TrimSpace(gjson.GetBytes(payload, "type").String())
	model := strings.TrimSpace(gjson.GetBytes(payload, "model").String())
	previousResponseID := strings.TrimSpace(gjson.GetBytes(payload, "previous_response_id").String())
	previousResponseIDKind := ClassifyOpenAIPreviousResponseIDKind(previousResponseID)
	promptCacheKey := strings.TrimSpace(gjson.GetBytes(payload, "prompt_cache_key").String())
	reasoningEffort := strings.TrimSpace(gjson.GetBytes(payload, "reasoning.effort").String())
	if reasoningEffort == "" {
		reasoningEffort = strings.TrimSpace(gjson.GetBytes(payload, "reasoning_effort").String())
	}
	serviceTier := strings.TrimSpace(gjson.GetBytes(payload, "service_tier").String())
	lowerPayload := strings.ToLower(string(payload))
	compactHint := strings.Contains(lowerPayload, "compact") ||
		strings.Contains(lowerPayload, "summariz") ||
		strings.Contains(lowerPayload, "summary")
	instructionsLen := len(gjson.GetBytes(payload, "instructions").String())
	inputItems := 0
	if input := gjson.GetBytes(payload, "input"); input.IsArray() {
		inputItems = len(input.Array())
	}
	toolCount := 0
	if tools := gjson.GetBytes(payload, "tools"); tools.IsArray() {
		toolCount = len(tools.Array())
	}
	logOpenAIWSV2Passthrough(
		"%s account_id=%d turn=%d type=%s model=%s payload_bytes=%d input_items=%d input_summary=%s instructions_len=%d tools=%d stream=%s store=%s previous_response_id=%s previous_response_id_kind=%s has_prompt_cache_key=%v service_tier=%s reasoning_effort=%s compact_hint=%v",
		prefix,
		accountID,
		turn,
		truncateOpenAIWSLogValue(eventType, openAIWSLogValueMaxLen),
		truncateOpenAIWSLogValue(model, openAIWSLogValueMaxLen),
		len(payload),
		inputItems,
		truncateOpenAIWSLogValue(openAIWSPassthroughFrameInputSummary(payload), openAIWSLogValueMaxLen),
		instructionsLen,
		toolCount,
		openAIWSPassthroughPayloadBoolForLog(payload, "stream"),
		openAIWSPassthroughPayloadBoolForLog(payload, "store"),
		truncateOpenAIWSLogValue(previousResponseID, openAIWSIDValueMaxLen),
		normalizeOpenAIWSLogValue(previousResponseIDKind),
		promptCacheKey != "",
		truncateOpenAIWSLogValue(serviceTier, openAIWSLogValueMaxLen),
		truncateOpenAIWSLogValue(reasoningEffort, openAIWSLogValueMaxLen),
		compactHint,
	)
}

const openaiWSV2PassthroughModeFields = "ws_mode=passthrough ws_router=v2"

var _ openaiwsv2.FrameConn = (*openAIWSClientFrameConn)(nil)

func (c *openAIWSClientFrameConn) ReadFrame(ctx context.Context) (coderws.MessageType, []byte, error) {
	if c == nil || c.conn == nil {
		return coderws.MessageText, nil, errOpenAIWSConnClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return c.conn.Read(ctx)
}

func (c *openAIWSClientFrameConn) WriteFrame(ctx context.Context, msgType coderws.MessageType, payload []byte) error {
	if c == nil || c.conn == nil {
		return errOpenAIWSConnClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return c.conn.Write(ctx, msgType, payload)
}

func (c *openAIWSClientFrameConn) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	_ = c.conn.Close(coderws.StatusNormalClosure, "")
	_ = c.conn.CloseNow()
	return nil
}

func (s *OpenAIGatewayService) proxyResponsesWebSocketV2Passthrough(
	ctx context.Context,
	c *gin.Context,
	clientConn *coderws.Conn,
	account *Account,
	token string,
	firstClientMessage []byte,
	hooks *OpenAIWSIngressHooks,
	wsDecision OpenAIWSProtocolDecision,
) error {
	if s == nil {
		return errors.New("service is nil")
	}
	if clientConn == nil {
		return errors.New("client websocket is nil")
	}
	if account == nil {
		return errors.New("account is nil")
	}
	if strings.TrimSpace(token) == "" {
		return errors.New("token is empty")
	}
	requestModel := strings.TrimSpace(gjson.GetBytes(firstClientMessage, "model").String())
	requestPreviousResponseID := strings.TrimSpace(gjson.GetBytes(firstClientMessage, "previous_response_id").String())
	logOpenAIWSV2Passthrough(
		"relay_start account_id=%d model=%s previous_response_id=%s first_message_type=%s first_message_bytes=%d",
		account.ID,
		truncateOpenAIWSLogValue(requestModel, openAIWSLogValueMaxLen),
		truncateOpenAIWSLogValue(requestPreviousResponseID, openAIWSIDValueMaxLen),
		openaiwsv2RelayMessageTypeName(coderws.MessageText),
		len(firstClientMessage),
	)

	// Apply OpenAI Fast Policy on the first response.create frame. Subsequent
	// frames are filtered via a wrapping FrameConn below so every client→
	// upstream frame goes through the same policy evaluator/normalize/scope as
	// HTTP entrypoints.
	//
	// We capture the session-level model from the first frame here so the
	// per-frame filter (below) can fall back to it when a follow-up frame
	// omits "model" — Realtime clients are allowed to send response.create
	// without re-stating the model, in which case the upstream uses the model
	// negotiated at session.update time. Without this fallback, an empty
	// model would miss any admin-configured model whitelist and be silently
	// passed through, defeating that policy on every frame after the first.
	capturedSessionModel := openAIWSPassthroughPolicyModelForFrame(account, firstClientMessage)
	initialRequestModel := ""
	if hooks != nil {
		initialRequestModel = hooks.InitialRequestModel
	}
	usageMeta := newOpenAIWSPassthroughUsageMeta(initialRequestModel, firstClientMessage)
	updatedFirst, blocked, policyErr := s.applyOpenAIFastPolicyToWSResponseCreate(ctx, account, capturedSessionModel, firstClientMessage)
	if policyErr != nil {
		return fmt.Errorf("apply openai fast policy on first ws frame: %w", policyErr)
	}
	if blocked != nil {
		MarkOpsClientBusinessLimited(c, OpsClientBusinessLimitedReasonLocalPolicyDenied)
		// coder/websocket@v1.8.14 Conn.Write is synchronous: it acquires
		// writeFrameMu, writes the entire frame, and Flushes the underlying
		// bufio writer before returning (write.go:42 → write.go:307-311).
		// The subsequent close handshake re-acquires the same writeFrameMu
		// to send the close frame, so the error event is guaranteed to
		// reach the kernel send buffer before any close frame is queued.
		// No explicit flush hop is required here.
		eventBytes := buildOpenAIFastPolicyBlockedWSEvent(blocked)
		if eventBytes != nil {
			writeCtx, cancelWrite := context.WithTimeout(ctx, s.openAIWSWriteTimeout())
			_ = clientConn.Write(writeCtx, coderws.MessageText, eventBytes)
			cancelWrite()
		}
		return NewOpenAIWSClientCloseError(coderws.StatusPolicyViolation, blocked.Message, blocked)
	}
	firstClientMessage = updatedFirst

	// 在 policy filter 之后再提取 service_tier / reasoning_effort 用于
	// usage 上报：filter
	// 命中时 service_tier 已经从 firstClientMessage 中删除，billing 应当
	// 反映上游实际处理的 tier（nil = default），而不是用户最初请求的
	// "priority"。HTTP 入口（line ~2728 extractOpenAIServiceTier(reqBody)）
	// 与 WS ingress（openai_ws_forwarder.go:2991 取自 payload）的语义一致。
	//
	// 多轮 passthrough：OpenAI Realtime / Responses WS 协议允许客户端在
	// 同一连接的不同 response.create 帧上发送不同 service_tier（参考
	// codex-rs/core/src/client.rs build_responses_request 每次重新填值）。
	// 因此使用 atomic.Pointer[string] 在 filter（runClientToUpstream
	// goroutine）和 OnTurnComplete / final result（runUpstreamToClient
	// goroutine）之间同步当前 turn 的 usage metadata。
	usageMeta.initFromFirstFrame(firstClientMessage, capturedSessionModel)
	logOpenAIWSV2PassthroughFrame("relay_first_request_frame", account.ID, 1, firstClientMessage)
	promptCacheKey := strings.TrimSpace(gjson.GetBytes(firstClientMessage, "prompt_cache_key").String())

	wsURL, err := s.buildOpenAIResponsesWSURL(account)
	if err != nil {
		return fmt.Errorf("build ws url: %w", err)
	}
	wsHost := "-"
	wsPath := "-"
	if parsedURL, parseErr := url.Parse(wsURL); parseErr == nil && parsedURL != nil {
		wsHost = normalizeOpenAIWSLogValue(parsedURL.Host)
		wsPath = normalizeOpenAIWSLogValue(parsedURL.Path)
	}
	logOpenAIWSV2Passthrough(
		"relay_dial_start account_id=%d ws_host=%s ws_path=%s proxy_enabled=%v",
		account.ID,
		wsHost,
		wsPath,
		account.ProxyID != nil && account.Proxy != nil,
	)

	isCodexCLI := false
	if c != nil {
		isCodexCLI = openai.IsCodexOfficialClientByHeaders(c.GetHeader("User-Agent"), c.GetHeader("originator"))
	}
	if s.cfg != nil && s.cfg.Gateway.ForceCodexCLI {
		isCodexCLI = true
	}
	turnState := ""
	turnMetadata := ""
	if c != nil {
		turnState = strings.TrimSpace(c.GetHeader(openAIWSTurnStateHeader))
		turnMetadata = strings.TrimSpace(c.GetHeader(openAIWSTurnMetadataHeader))
	}
	headers, _, buildHdrErr := s.buildOpenAIWSHeaders(ctx, c, account, token, wsDecision, isCodexCLI, turnState, turnMetadata, promptCacheKey)
	if buildHdrErr != nil {
		return fmt.Errorf("build ws headers: %w", buildHdrErr)
	}
	proxyURL := ""
	if account.ProxyID != nil && account.Proxy != nil {
		proxyURL = account.Proxy.URL()
	}

	dialer := s.getOpenAIWSPassthroughDialer()
	if dialer == nil {
		return errors.New("openai ws passthrough dialer is nil")
	}

	dialCtx, cancelDial := context.WithTimeout(ctx, s.openAIWSDialTimeout())
	defer cancelDial()
	upstreamConn, statusCode, handshakeHeaders, err := dialer.Dial(dialCtx, wsURL, headers, proxyURL)
	if err != nil {
		logOpenAIWSV2Passthrough(
			"relay_dial_failed account_id=%d status_code=%d err=%s",
			account.ID,
			statusCode,
			truncateOpenAIWSLogValue(err.Error(), openAIWSLogValueMaxLen),
		)
		if statusCode == http.StatusTooManyRequests {
			s.persistOpenAIWSRateLimitSignal(ctx, account, handshakeHeaders, nil, "rate_limit_exceeded", "rate_limit_error", strings.TrimSpace(err.Error()))
			return &UpstreamFailoverError{
				StatusCode:      http.StatusTooManyRequests,
				ResponseHeaders: cloneHeader(handshakeHeaders),
			}
		}
		return s.mapOpenAIWSPassthroughDialError(err, statusCode, handshakeHeaders)
	}
	defer func() {
		_ = upstreamConn.Close()
	}()
	logOpenAIWSV2Passthrough(
		"relay_dial_ok account_id=%d status_code=%d upstream_request_id=%s",
		account.ID,
		statusCode,
		openAIWSHeaderValueForLog(handshakeHeaders, "x-request-id"),
	)

	upstreamFrameConn, ok := upstreamConn.(openaiwsv2.FrameConn)
	if !ok {
		return errors.New("openai ws passthrough upstream connection does not support frame relay")
	}
	stopUpstreamKeepalive := s.startOpenAIWSPassthroughUpstreamKeepalive(ctx, upstreamConn, account.ID)
	defer stopUpstreamKeepalive()

	completedTurns := atomic.Int32{}
	policyClientConn := &openAIWSPolicyEnforcingFrameConn{
		inner: &openAIWSClientFrameConn{conn: clientConn},
		// 注意线程安全：filter 仅在 runClientToUpstream 这一条
		// goroutine 中被调用（passthrough_relay.go: ReadFrame loop），
		// capturedSessionModel 的读写都发生在该 goroutine 内，因此无需
		// 加锁/原子化。
		filter: func(msgType coderws.MessageType, payload []byte) ([]byte, *OpenAIFastBlockedError, error) {
			if msgType != coderws.MessageText {
				return payload, nil, nil
			}
			frameType := strings.TrimSpace(gjson.GetBytes(payload, "type").String())
			turnNo := int(completedTurns.Load()) + 1
			if turnNo < 2 {
				turnNo = 2
			}
			if frameType == "response.create" && hooks != nil && hooks.BeforeRequest != nil {
				requestModel := usageMeta.requestModelForFrame(payload)
				if requestModel == "" {
					requestModel = capturedSessionModel
				}
				if err := hooks.BeforeRequest(turnNo, payload, requestModel); err != nil {
					return payload, nil, err
				}
			}
			// 在评估策略前先刷新 capturedSessionModel：客户端可能通过
			// session.update 修改 session-level model（Realtime /
			// Responses WS 协议允许），如果不刷新就会出现
			// "首帧 model=gpt-4o（pass）→ session.update 改成 gpt-5.5
			// → 不带 model 的 response.create fallback 到 gpt-4o" 的
			// 绕过路径。这里只看 session.update 事件中的 session.model
			// 字段，response.create 自己的 model 仍然由其本帧字段决定。
			if updated := openAIWSPassthroughPolicyModelFromSessionFrame(account, payload); updated != "" {
				capturedSessionModel = updated
			}
			usageMeta.updateSessionRequestModel(payload)
			requestModelForThisFrame := usageMeta.requestModelForFrame(payload)
			// Per-frame model first; if the client omits "model" on a
			// follow-up frame (legal in Realtime), fall back to the
			// session-level model captured from the first frame so the
			// model whitelist still resolves. An empty model would miss
			// any whitelist and silently fall back to pass.
			model := openAIWSPassthroughPolicyModelForFrame(account, payload)
			if model == "" {
				model = capturedSessionModel
			}
			out, blocked, policyErr := s.applyOpenAIFastPolicyToWSResponseCreate(ctx, account, model, payload)
			// 多轮 passthrough usage：仅在成功（non-block / non-err）
			// 的 response.create 帧上更新 usageMeta，使用
			// filter 处理后的 payload，与首帧 policy-after-extract 语义
			// 保持一致（参见上方 extractOpenAIServiceTierFromBody 注释）。
			//   - 非 response.create 帧（response.cancel /
			//     conversation.item.create / session.update 等）不携带
			//     per-response metadata，不应覆盖前一轮值。
			//   - blocked != nil：该帧不会发送上游，usage metadata 应保持
			//     上一轮值。
			//   - policyErr != nil：异常路径，保持上一轮值。
			//   - 不带 service_tier 的 response.create 会让
			//     extractOpenAIServiceTierFromBody 返回 nil；这里有意
			//     覆盖（Store(nil)），因为 OpenAI 上游对该帧实际不传
			//     service_tier 时按 default 处理，billing 应如实反映。
			if policyErr == nil && blocked == nil &&
				frameType == "response.create" {
				usageMeta.updateFromResponseCreate(out, model, requestModelForThisFrame)
			}
			if frameType == "response.create" {
				logOpenAIWSV2PassthroughFrame("relay_request_frame", account.ID, turnNo, out)
			}
			return out, blocked, policyErr
		},
		onBlock: func(blocked *OpenAIFastBlockedError) {
			MarkOpsClientBusinessLimited(c, OpsClientBusinessLimitedReasonLocalPolicyDenied)
			// See note above on Conn.Write being synchronous w.r.t. flush;
			// no explicit flush is required to ensure the error event lands
			// before the close frame.
			eventBytes := buildOpenAIFastPolicyBlockedWSEvent(blocked)
			if eventBytes == nil {
				return
			}
			writeCtx, cancel := context.WithTimeout(ctx, s.openAIWSWriteTimeout())
			_ = clientConn.Write(writeCtx, coderws.MessageText, eventBytes)
			cancel()
		},
	}
	upstreamFirstMessageSent := false
	firstWriteCtx, cancelFirstWrite := context.WithTimeout(ctx, s.openAIWSWriteTimeout())
	firstWriteErr := upstreamFrameConn.WriteFrame(firstWriteCtx, coderws.MessageText, firstClientMessage)
	cancelFirstWrite()
	if firstWriteErr != nil {
		return wrapOpenAIWSIngressTurnError(
			"write_upstream",
			fmt.Errorf("write first upstream websocket request: %w", firstWriteErr),
			false,
		)
	}
	upstreamFirstMessageSent = true

	readNextClientFrame := func(readCtx context.Context, conn openaiwsv2.FrameConn) (coderws.MessageType, []byte, error) {
		for {
			msgType, payload, readErr := conn.ReadFrame(readCtx)
			if readErr != nil {
				return msgType, payload, readErr
			}
			if msgType == coderws.MessageText && strings.TrimSpace(gjson.GetBytes(payload, "type").String()) == "response.create" {
				return msgType, payload, nil
			}
			if msgType == coderws.MessageText {
				logOpenAIWSV2PassthroughFrame("relay_client_control_frame", account.ID, int(completedTurns.Load())+1, payload)
			} else {
				logOpenAIWSV2Passthrough(
					"relay_client_control_frame account_id=%d turn=%d type=- msg_type=%s payload_bytes=%d",
					account.ID,
					int(completedTurns.Load())+1,
					openaiwsv2RelayMessageTypeName(msgType),
					len(payload),
				)
			}
			if writeErr := upstreamFrameConn.WriteFrame(readCtx, msgType, payload); writeErr != nil {
				return msgType, payload, writeErr
			}
		}
	}

	relayResult, relayExit := openaiwsv2.RunEntry(openaiwsv2.EntryInput{
		Ctx:                ctx,
		ClientConn:         policyClientConn,
		UpstreamConn:       upstreamFrameConn,
		FirstClientMessage: firstClientMessage,
		Options: openaiwsv2.RelayOptions{
			WriteTimeout:                       s.openAIWSWriteTimeout(),
			IdleTimeout:                        s.openAIWSPassthroughIdleTimeout(),
			FirstMessageType:                   coderws.MessageText,
			FirstMessageSent:                   upstreamFirstMessageSent,
			StartClientAfterFirstDownstream:    true,
			RequireTerminalBeforeUpstreamClose: true,
			ReadClientFrame:                    readNextClientFrame,
			OnUsageParseFailure: func(eventType string, usageRaw string) {
				logOpenAIWSV2Passthrough(
					"usage_parse_failed event_type=%s usage_raw=%s",
					truncateOpenAIWSLogValue(eventType, openAIWSLogValueMaxLen),
					truncateOpenAIWSLogValue(usageRaw, openAIWSLogValueMaxLen),
				)
			},
			OnTurnComplete: func(turn openaiwsv2.RelayTurnResult) {
				turnNo := int(completedTurns.Add(1))
				turnResult := &OpenAIForwardResult{
					RequestID: turn.RequestID,
					Usage: OpenAIUsage{
						InputTokens:              turn.Usage.InputTokens,
						OutputTokens:             turn.Usage.OutputTokens,
						CacheCreationInputTokens: turn.Usage.CacheCreationInputTokens,
						CacheReadInputTokens:     turn.Usage.CacheReadInputTokens,
						ImageOutputTokens:        turn.Usage.ImageOutputTokens,
					},
					Model:           turn.RequestModel,
					ServiceTier:     usageMeta.serviceTier.Load(),
					ReasoningEffort: usageMeta.reasoningEffort.Load(),
					Stream:          true,
					OpenAIWSMode:    true,
					ResponseHeaders: cloneHeader(handshakeHeaders),
					Duration:        turn.Duration,
					FirstTokenMs:    turn.FirstTokenMs,
				}
				logOpenAIWSV2Passthrough(
					"relay_turn_completed account_id=%d turn=%d request_id=%s terminal_event=%s duration_ms=%d first_token_ms=%d input_tokens=%d output_tokens=%d cache_read_tokens=%d",
					account.ID,
					turnNo,
					truncateOpenAIWSLogValue(turnResult.RequestID, openAIWSIDValueMaxLen),
					truncateOpenAIWSLogValue(turn.TerminalEventType, openAIWSLogValueMaxLen),
					turnResult.Duration.Milliseconds(),
					openAIWSFirstTokenMsForLog(turnResult.FirstTokenMs),
					turnResult.Usage.InputTokens,
					turnResult.Usage.OutputTokens,
					turnResult.Usage.CacheReadInputTokens,
				)
				if hooks != nil && hooks.AfterTurn != nil {
					hooks.AfterTurn(turnNo, turnResult, nil)
				}
			},
			BeforeWriteClient: func(msgType coderws.MessageType, payload []byte, wroteDownstream bool) error {
				if msgType != coderws.MessageText || wroteDownstream {
					return nil
				}
				if eventType, _, _ := parseOpenAIWSEventEnvelope(payload); eventType != "error" {
					return nil
				}
				errCodeRaw, errTypeRaw, errMsgRaw := parseOpenAIWSErrorEventFields(payload)
				if !isOpenAIWSRateLimitError(errCodeRaw, errTypeRaw, errMsgRaw) {
					return nil
				}
				s.persistOpenAIWSRateLimitSignal(ctx, account, handshakeHeaders, payload, errCodeRaw, errTypeRaw, errMsgRaw)
				logOpenAIWSV2Passthrough(
					"relay_rate_limit_failover account_id=%d err_code=%s err_type=%s err_message=%s",
					account.ID,
					truncateOpenAIWSLogValue(errCodeRaw, openAIWSLogValueMaxLen),
					truncateOpenAIWSLogValue(errTypeRaw, openAIWSLogValueMaxLen),
					truncateOpenAIWSLogValue(errMsgRaw, openAIWSLogValueMaxLen),
				)
				return &UpstreamFailoverError{
					StatusCode:      http.StatusTooManyRequests,
					ResponseBody:    append([]byte(nil), payload...),
					ResponseHeaders: cloneHeader(handshakeHeaders),
				}
			},
			OnTrace: func(event openaiwsv2.RelayTraceEvent) {
				logOpenAIWSV2Passthrough(
					"relay_trace account_id=%d stage=%s direction=%s msg_type=%s bytes=%d graceful=%v wrote_downstream=%v close_status=%s close_reason=%s err=%s",
					account.ID,
					normalizeOpenAIWSLogEnum(event.Stage),
					normalizeOpenAIWSLogEnum(event.Direction),
					normalizeOpenAIWSLogEnum(event.MessageType),
					event.PayloadBytes,
					event.Graceful,
					event.WroteDownstream,
					truncateOpenAIWSLogValue(event.CloseStatus, openAIWSLogValueMaxLen),
					truncateOpenAIWSLogValue(event.CloseReason, openAIWSLogValueMaxLen),
					truncateOpenAIWSLogValue(event.Error, openAIWSLogValueMaxLen),
				)
			},
		},
	})

	result := &OpenAIForwardResult{
		RequestID: relayResult.RequestID,
		Usage: OpenAIUsage{
			InputTokens:              relayResult.Usage.InputTokens,
			OutputTokens:             relayResult.Usage.OutputTokens,
			CacheCreationInputTokens: relayResult.Usage.CacheCreationInputTokens,
			CacheReadInputTokens:     relayResult.Usage.CacheReadInputTokens,
			ImageOutputTokens:        relayResult.Usage.ImageOutputTokens,
		},
		Model:           relayResult.RequestModel,
		ServiceTier:     usageMeta.serviceTier.Load(),
		ReasoningEffort: usageMeta.reasoningEffort.Load(),
		Stream:          true,
		OpenAIWSMode:    true,
		ResponseHeaders: cloneHeader(handshakeHeaders),
		Duration:        relayResult.Duration,
		FirstTokenMs:    relayResult.FirstTokenMs,
	}

	turnCount := int(completedTurns.Load())
	if relayExit == nil {
		logOpenAIWSV2PassthroughResult("relay_completed", account.ID, result, relayResult, nil, turnCount)
		// 正常路径按 terminal 事件逐 turn 已回调；仅在零 turn 场景兜底回调一次。
		if turnCount == 0 && hooks != nil && hooks.AfterTurn != nil {
			hooks.AfterTurn(1, result, nil)
		}
		return nil
	}
	logOpenAIWSV2PassthroughResult("relay_failed", account.ID, result, relayResult, relayExit, turnCount)

	relayErr := relayExit.Err
	if relayExit.Stage == "idle_timeout" {
		relayErr = NewOpenAIWSClientCloseError(
			coderws.StatusPolicyViolation,
			"client websocket idle timeout",
			relayErr,
		)
	}
	turnErr := wrapOpenAIWSIngressTurnError(
		relayExit.Stage,
		relayErr,
		relayExit.WroteDownstream,
	)
	if hooks != nil && hooks.AfterTurn != nil {
		hooks.AfterTurn(turnCount+1, nil, turnErr)
	}
	return turnErr
}

func (s *OpenAIGatewayService) mapOpenAIWSPassthroughDialError(
	err error,
	statusCode int,
	handshakeHeaders http.Header,
) error {
	if err == nil {
		return nil
	}
	wrappedErr := err
	var dialErr *openAIWSDialError
	if !errors.As(err, &dialErr) {
		wrappedErr = &openAIWSDialError{
			StatusCode:      statusCode,
			ResponseHeaders: cloneHeader(handshakeHeaders),
			Err:             err,
		}
	}

	if errors.Is(err, context.Canceled) {
		return err
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return NewOpenAIWSClientCloseError(
			coderws.StatusTryAgainLater,
			"upstream websocket connect timeout",
			wrappedErr,
		)
	}
	if statusCode == http.StatusTooManyRequests {
		return NewOpenAIWSClientCloseError(
			coderws.StatusTryAgainLater,
			"upstream websocket is busy, please retry later",
			wrappedErr,
		)
	}
	if statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden {
		return NewOpenAIWSClientCloseError(
			coderws.StatusPolicyViolation,
			"upstream websocket authentication failed",
			wrappedErr,
		)
	}
	if statusCode >= http.StatusBadRequest && statusCode < http.StatusInternalServerError {
		return NewOpenAIWSClientCloseError(
			coderws.StatusPolicyViolation,
			"upstream websocket handshake rejected",
			wrappedErr,
		)
	}
	return fmt.Errorf("openai ws passthrough dial: %w", wrappedErr)
}

func openaiwsv2RelayMessageTypeName(msgType coderws.MessageType) string {
	switch msgType {
	case coderws.MessageText:
		return "text"
	case coderws.MessageBinary:
		return "binary"
	default:
		return fmt.Sprintf("unknown(%d)", msgType)
	}
}

func relayErrorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func logOpenAIWSV2PassthroughResult(
	event string,
	accountID int64,
	result *OpenAIForwardResult,
	relayResult openaiwsv2.RelayResult,
	relayExit *openaiwsv2.RelayExit,
	turnCount int,
) {
	durationMS := int64(0)
	requestID := ""
	if result != nil {
		durationMS = result.Duration.Milliseconds()
		requestID = result.RequestID
	}

	fields := []zap.Field{
		zap.String("component", "service.openai_ws_v2"),
		zap.String("ws_mode", "passthrough"),
		zap.String("ws_router", "v2"),
		zap.Int64("account_id", accountID),
		zap.String("request_id", truncateOpenAIWSLogValue(requestID, openAIWSIDValueMaxLen)),
		zap.String("terminal_event", normalizeOpenAIWSLogEnum(relayResult.TerminalEventType)),
		zap.Int64("duration_ms", durationMS),
		zap.Int64("c2u_frames", relayResult.ClientToUpstreamFrames),
		zap.Int64("u2c_frames", relayResult.UpstreamToClientFrames),
		zap.Int64("dropped_frames", relayResult.DroppedDownstreamFrames),
		zap.Int("turns", turnCount),
		zap.String("first_exit_stage", normalizeOpenAIWSLogEnum(relayResult.FirstExitStage)),
		zap.String("first_exit_close_status", truncateOpenAIWSLogValue(relayResult.FirstExitCloseStatus, openAIWSLogValueMaxLen)),
		zap.String("first_exit_close_reason", truncateOpenAIWSLogValue(relayResult.FirstExitCloseReason, openAIWSHeaderValueMaxLen)),
		zap.Bool("first_exit_graceful", relayResult.FirstExitGraceful),
		zap.Bool("first_exit_wrote_downstream", relayResult.FirstExitWroteDownstream),
		zap.String("first_exit_err", truncateOpenAIWSLogValue(relayResult.FirstExitError, openAIWSLogValueMaxLen)),
		zap.Bool("has_second_exit", relayResult.HasSecondExit),
		zap.String("second_exit_stage", normalizeOpenAIWSLogEnum(relayResult.SecondExitStage)),
		zap.String("second_exit_close_status", truncateOpenAIWSLogValue(relayResult.SecondExitCloseStatus, openAIWSLogValueMaxLen)),
		zap.String("second_exit_close_reason", truncateOpenAIWSLogValue(relayResult.SecondExitCloseReason, openAIWSHeaderValueMaxLen)),
		zap.Bool("second_exit_graceful", relayResult.SecondExitGraceful),
		zap.Bool("second_exit_wrote_downstream", relayResult.SecondExitWroteDownstream),
		zap.String("second_exit_err", truncateOpenAIWSLogValue(relayResult.SecondExitError, openAIWSLogValueMaxLen)),
		zap.Bool("client_closed_first", relayResult.ClientClosedFirst),
		zap.Bool("terminal_observed", relayResult.TerminalObserved),
	}
	if relayExit != nil {
		closeStatus, closeReason := summarizeOpenAIWSReadCloseError(relayExit.Err)
		fields = append(fields,
			zap.String("stage", normalizeOpenAIWSLogEnum(relayExit.Stage)),
			zap.Bool("wrote_downstream", relayExit.WroteDownstream),
			zap.String("close_status", closeStatus),
			zap.String("close_reason", truncateOpenAIWSLogValue(closeReason, openAIWSHeaderValueMaxLen)),
			zap.String("err", truncateOpenAIWSLogValue(relayErrorText(relayExit.Err), openAIWSLogValueMaxLen)),
		)
	}

	logOpenAIWSV2Passthrough(
		"relay_result_summary event=%s account_id=%d request_id=%s terminal_event=%s duration_ms=%d turns=%d c2u_frames=%d u2c_frames=%d dropped_frames=%d first_exit_stage=%s first_exit_graceful=%v first_exit_wrote_downstream=%v first_exit_close_status=%s has_second_exit=%v second_exit_stage=%s second_exit_graceful=%v second_exit_wrote_downstream=%v client_closed_first=%v terminal_observed=%v",
		event,
		accountID,
		truncateOpenAIWSLogValue(requestID, openAIWSIDValueMaxLen),
		normalizeOpenAIWSLogEnum(relayResult.TerminalEventType),
		durationMS,
		turnCount,
		relayResult.ClientToUpstreamFrames,
		relayResult.UpstreamToClientFrames,
		relayResult.DroppedDownstreamFrames,
		normalizeOpenAIWSLogEnum(relayResult.FirstExitStage),
		relayResult.FirstExitGraceful,
		relayResult.FirstExitWroteDownstream,
		truncateOpenAIWSLogValue(relayResult.FirstExitCloseStatus, openAIWSLogValueMaxLen),
		relayResult.HasSecondExit,
		normalizeOpenAIWSLogEnum(relayResult.SecondExitStage),
		relayResult.SecondExitGraceful,
		relayResult.SecondExitWroteDownstream,
		relayResult.ClientClosedFirst,
		relayResult.TerminalObserved,
	)
	logger.L().Info("openai_ws_v2_passthrough."+event, fields...)
}

func openAIWSFirstTokenMsForLog(firstTokenMs *int) int {
	if firstTokenMs == nil {
		return -1
	}
	return *firstTokenMs
}

func logOpenAIWSV2Passthrough(format string, args ...any) {
	logger.LegacyPrintf(
		"service.openai_ws_v2",
		"[OpenAI WS v2 passthrough] %s "+format,
		append([]any{openaiWSV2PassthroughModeFields}, args...)...,
	)
}
