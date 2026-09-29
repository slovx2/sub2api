package service

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/ctxkey"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

func TestBPSImageBudgetReleaseAndLimits(t *testing.T) {
	b := &bpsImageAdmissionBudget{}
	release, ok := b.acquire(64<<20, "large")
	require.True(t, ok)
	_, ok = b.acquire(1, "small")
	require.False(t, ok)
	release()
	release()
	require.Zero(t, b.bytes)
	require.Zero(t, b.requests)
	var releases []func()
	for i := 0; i < 32; i++ {
		r, acquired := b.acquire(1, "small")
		require.True(t, acquired)
		releases = append(releases, r)
	}
	_, ok = b.acquire(1, "overflow")
	require.False(t, ok)
	for _, r := range releases {
		r()
	}
	require.Zero(t, b.bytes)
}

// 经过真实转发入口验证：上游流未结束时额度仍持有，取消后才释放。
type bpsBudgetBlockedBody struct {
	ctx     context.Context
	entered chan struct{}
}

func (b *bpsBudgetBlockedBody) Read([]byte) (int, error) {
	select {
	case <-b.entered:
	default:
		close(b.entered)
	}
	<-b.ctx.Done()
	return 0, b.ctx.Err()
}

func (b *bpsBudgetBlockedBody) Close() error { return nil }

func TestBPSImageBudgetForwardCancellation(t *testing.T) {
	t.Setenv("DATA_DIR", t.TempDir())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reader := &bpsBudgetBlockedBody{ctx: ctx, entered: make(chan struct{})}
	upstream := &httpUpstreamRecorder{resp: &http.Response{
		StatusCode: 200, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: reader,
	}}
	svc := openAIClientToolsTestService(upstream)
	svc.settingService = NewSettingService(&excelBPSImageSettingsRepo{values: map[string]string{
		SettingKeyExcelBPSImageRelayEnabled: "true", SettingKeyExcelBPSImageBaseURL: "https://images.example",
	}}, svc.cfg)
	t.Cleanup(func() { require.NoError(t, svc.CloseExcelBPSImages()) })
	body := []byte(`{"model":"gpt-6-astra","stream":true,"input":[{"role":"user","content":[{"type":"input_image","image_url":"https://images.example/photo.png"}]}]}`)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("POST", "/v1/responses", bytes.NewReader(body)).WithContext(ctx)
	done := make(chan error, 1)
	go func() { _, err := svc.Forward(ctx, c, excelAccount(), body); done <- err }()
	select {
	case <-reader.entered:
	case err := <-done:
		t.Fatalf("未进入上游读取: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("未进入上游读取")
	}
	svc.excelBPSImageBudget.mu.Lock()
	requests, held := svc.excelBPSImageBudget.requests, svc.excelBPSImageBudget.bytes
	svc.excelBPSImageBudget.mu.Unlock()
	require.Equal(t, 1, requests)
	require.Positive(t, held)
	cancel()
	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("取消后转发未退出")
	}
	require.Zero(t, svc.excelBPSImageBudget.bytes)
	require.Zero(t, svc.excelBPSImageBudget.requests)
}

func TestBPSImageBudgetFullDoesNotBlockNativeForward(t *testing.T) {
	gpt := excelAccount()
	gpt.Extra["openai_excel_bps"] = false
	for name, account := range map[string]*Account{"gpt": gpt, "deepseek": deepSeekNativeResponsesImageAccount()} {
		t.Run(name, func(t *testing.T) {
			wire := "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_native\",\"status\":\"completed\",\"output\":[],\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}\n\n"
			upstream := &httpUpstreamRecorder{resp: &http.Response{
				StatusCode: 200, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: io.NopCloser(strings.NewReader(wire)),
			}}
			svc := openAIClientToolsTestService(upstream)
			release, ok := svc.excelBPSImageBudget.acquire(64<<20, "held")
			require.True(t, ok)
			defer release()
			body := []byte(`{"model":"deepseek-flash","stream":true,"input":[{"role":"user","content":[{"type":"input_image","image_url":"data:image/png;base64,AQID"}]}]}`)
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = httptest.NewRequest("POST", "/v1/responses", bytes.NewReader(body))
			result, err := svc.Forward(context.Background(), c, account, body)
			require.NoError(t, err)
			require.NotNil(t, result)
			require.NotEmpty(t, upstream.requests)
			require.Equal(t, 1, svc.excelBPSImageBudget.requests)
		})
	}
}

func TestBPSImageBudgetFailureAndTextIsolation(t *testing.T) {
	svc := &OpenAIGatewayService{cfg: deepSeekChatFallbackTestConfig()}
	release, ok := svc.excelBPSImageBudget.acquire(64<<20, "held")
	require.True(t, ok)
	defer release()
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	_, err := svc.forwardExcelBPS(context.Background(), c, &Account{}, []byte(`{"input":[{"type":"input_image","image_url":"data:image/png;base64,AQID"}]}`), time.Now())
	require.ErrorContains(t, err, "basispoints_image_request_busy")
	// 普通协议使用独立的出站路径，BPS 满额也能构造并发送请求。
	body := deepSeekUserImageBody(`{"type":"input_image","image_url":"` + deepSeekInputImageDataURI + `"}`)
	c = newDeepSeekChatFallbackContext(t, body)
	req, err := svc.buildUpstreamRequest(context.Background(), c, deepSeekNativeResponsesImageAccount(), body, "test", false, "", false)
	require.NoError(t, err)
	require.Equal(t, "api.deepseek.com", req.URL.Hostname())
	require.Equal(t, 1, responsesImageCount(body))
	require.Zero(t, responsesImageCount([]byte(`{"input":[{"type":"input_text","text":"input_image"}]}`)))
}

func TestDeepSeekImagesSingleCopyAndProtocolIsolation(t *testing.T) {
	for _, part := range []string{
		`{"type":"input_image","image_url":"` + deepSeekInputImageDataURI + `","url":"` + deepSeekInputImageDataURI + `"}`,
		`{"type":"image","source":{"type":"base64","media_type":"image/png","data":"AQID"}}`,
	} {
		body := deepSeekUserImageBody(part)
		original := bytes.Clone(body)
		got := normalizeDeepSeekResponsesRequestBody(deepSeekNativeResponsesImageAccount(), body)
		require.Equal(t, 1, bytes.Count(got, []byte("AQID")))
		require.Equal(t, original, body, "账号处理不可修改供 failover 使用的原始字节")
		require.Equal(t, got, normalizeDeepSeekResponsesRequestBody(deepSeekNativeResponsesImageAccount(), got))
	}
	a := deepSeekNativeResponsesImageAccount()
	a.Credentials["api_protocol"] = "adaptive"
	a.Credentials["api_base_urls"] = map[string]any{APIProtocolResponses: "http://commandcode-proxy:3050/v1", APIProtocolChatCompletions: DefaultDeepseekBaseURL}
	require.False(t, shouldAliasDeepSeekResponsesInputImages(a))
	require.True(t, targetsDeepSeekAPIHost(a))
}

func TestResponsesBodyTooLargeEnvelope(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	err := writeResponsesBodyTooLarge(c, "https://api.deepseek.com/responses", 48<<20+1)
	require.Error(t, err)
	require.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
	require.Equal(t, "request_body_too_large", gjson.Get(w.Body.String(), "error.code").String())
	require.Equal(t, int64(48<<20), gjson.Get(w.Body.String(), "error.limit_bytes").Int())
	limit, source := responsesBodyLimit("http://commandcode-proxy:3050/v1/responses")
	require.Equal(t, 20<<20, limit)
	require.Equal(t, "commandcode_proxy_local", source)
}

func TestBPSImageBudgetCancellationReleasesCapacity(t *testing.T) {
	b := &bpsImageAdmissionBudget{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		release, acquired := b.acquire(64<<20, "cancel")
		if !acquired {
			return
		}
		defer release()
		close(entered)
		<-ctx.Done()
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("未获得额度")
	}
	_, acquired := b.acquire(1, "blocked")
	require.False(t, acquired)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("取消未释放")
	}
	release, acquired := b.acquire(64<<20, "next")
	require.True(t, acquired)
	release()
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("POST", "/responses", nil).WithContext(context.WithValue(context.Background(), ctxkey.RequestID, "request-example"))
	require.Equal(t, "request-example", imageBudgetRequestID(c))
}
