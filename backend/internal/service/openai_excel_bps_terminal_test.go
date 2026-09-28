package service

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

const (
	excelBPSBareErrorFrame = "event: error\ndata: {\"type\":\"error\",\"sequence_number\":2,\"error\":{\"type\":\"tokens\",\"code\":\"rate_limit_exceeded\",\"message\":\"Rate limit reached for gpt-6-sol in organization org-test on tokens per min (TPM): Limit 40000000. Please try again in 34ms.\"}}\n\n"
	excelBPSCreatedFrame   = "event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_bps_limit\"}}\n\n"
	excelBPSFailedFrame    = "event: response.failed\ndata: {\"type\":\"response.failed\",\"response\":{\"id\":\"resp_bps_limit\",\"status\":\"failed\",\"model\":\"gpt-6-sol\",\"output\":[],\"error\":{\"code\":\"rate_limit_exceeded\",\"message\":\"Rate limit reached for gpt-6-sol in organization org-test on tokens per min (TPM): Limit 40000000. Please try again in 34ms.\"}}}\n\n"
)

func forwardExcelBPSWire(t *testing.T, wire string) (*httptest.ResponseRecorder, error) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	upstream := &httpUpstreamRecorder{resp: &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"text/event-stream"}},
		Body:       io.NopCloser(strings.NewReader(wire)),
	}}
	svc := openAIClientToolsTestService(upstream)
	body := []byte(`{"model":"gpt-6-sol","stream":true,"input":"test"}`)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader(body))
	_, err := svc.Forward(context.Background(), c, excelAccount(), body)
	return rec, err
}

// The bare `error` frame BPS sends before `response.failed` must not close the
// stream, otherwise the client only sees "stream closed before response.completed".
func TestExcelBPSForwardsTerminalFailureAfterBareError(t *testing.T) {
	rec, err := forwardExcelBPSWire(t, excelBPSCreatedFrame+excelBPSBareErrorFrame+excelBPSFailedFrame)
	require.Error(t, err)
	require.Contains(t, err.Error(), "excel BPS terminal: response.failed")
	require.Contains(t, err.Error(), "Please try again in 34ms")

	body := rec.Body.String()
	require.Contains(t, body, "response.failed")
	require.Contains(t, body, "rate_limit_exceeded")
	require.Contains(t, body, "Please try again in 34ms")
	require.NotContains(t, body, "event: error\n")
}

// When the upstream never sends a terminal frame, the synthesized failure must
// carry the captured upstream error instead of a generic stream-not-complete code.
func TestExcelBPSSynthesizesTerminalFailureFromCapturedError(t *testing.T) {
	rec, err := forwardExcelBPSWire(t, excelBPSCreatedFrame+excelBPSBareErrorFrame)
	require.Error(t, err)
	require.Contains(t, err.Error(), "excel BPS stream incomplete")

	body := rec.Body.String()
	require.Contains(t, body, "response.failed")
	require.Contains(t, body, "rate_limit_exceeded")
	require.Contains(t, body, "Please try again in 34ms")
	require.NotContains(t, body, "basispoints_stream_incomplete")
	require.NotContains(t, body, "event: error\n")
}

func TestExcelBPSSynthesizesGenericFailureWithoutAnErrorFrame(t *testing.T) {
	rec, err := forwardExcelBPSWire(t, excelBPSCreatedFrame)
	require.Error(t, err)
	require.Contains(t, err.Error(), "excel BPS stream incomplete")

	body := rec.Body.String()
	require.Contains(t, body, "response.failed")
	require.Contains(t, body, "basispoints_stream_incomplete")
}
