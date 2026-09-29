package service

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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
