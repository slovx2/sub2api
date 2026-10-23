package service

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

type watchdogTestCloser struct {
	closed atomic.Int32
}

func (c *watchdogTestCloser) Close() error {
	c.closed.Add(1)
	return nil
}

func TestOpenAIPassthroughStreamWatchdogIdleTimeoutClosesBody(t *testing.T) {
	body := &watchdogTestCloser{}
	w := startOpenAIPassthroughStreamWatchdog(context.Background(), body, 30*time.Millisecond, time.Second)
	defer w.Stop()

	require.Eventually(t, func() bool { return body.closed.Load() == 1 }, time.Second, 5*time.Millisecond)
	require.Equal(t, openAIPassthroughStreamCutIdleTimeout, w.Reason())
}

func TestOpenAIPassthroughStreamWatchdogTouchDefersIdleTimeout(t *testing.T) {
	body := &watchdogTestCloser{}
	w := startOpenAIPassthroughStreamWatchdog(context.Background(), body, 80*time.Millisecond, time.Second)
	defer w.Stop()

	for i := 0; i < 5; i++ {
		time.Sleep(30 * time.Millisecond)
		w.Touch()
	}
	require.Zero(t, body.closed.Load())
	require.Equal(t, openAIPassthroughStreamCutNone, w.Reason())
}

func TestOpenAIPassthroughStreamWatchdogClientGoneBeforeOutputClosesImmediately(t *testing.T) {
	body := &watchdogTestCloser{}
	ctx, cancel := context.WithCancel(context.Background())
	w := startOpenAIPassthroughStreamWatchdog(ctx, body, 0, time.Hour)
	defer w.Stop()

	cancel()
	require.Eventually(t, func() bool { return body.closed.Load() == 1 }, time.Second, 5*time.Millisecond)
	require.Equal(t, openAIPassthroughStreamCutClientGone, w.Reason())
}

func TestOpenAIPassthroughStreamWatchdogClientGoneAfterOutputDrainsUntilTimeout(t *testing.T) {
	body := &watchdogTestCloser{}
	ctx, cancel := context.WithCancel(context.Background())
	w := startOpenAIPassthroughStreamWatchdog(ctx, body, 0, 100*time.Millisecond)
	defer w.Stop()

	w.MarkOutputStarted()
	cancel()
	time.Sleep(40 * time.Millisecond)
	require.Zero(t, body.closed.Load(), "已有输出时应先排空一段时间")
	require.Eventually(t, func() bool { return body.closed.Load() == 1 }, time.Second, 5*time.Millisecond)
	require.Equal(t, openAIPassthroughStreamCutDrainTimeout, w.Reason())
}

func TestOpenAIPassthroughStreamWatchdogStopPreventsFiring(t *testing.T) {
	body := &watchdogTestCloser{}
	ctx, cancel := context.WithCancel(context.Background())
	w := startOpenAIPassthroughStreamWatchdog(ctx, body, 20*time.Millisecond, time.Hour)

	w.Stop()
	cancel()
	time.Sleep(60 * time.Millisecond)
	require.Zero(t, body.closed.Load())
	require.Equal(t, openAIPassthroughStreamCutNone, w.Reason())
}

// newStalledPassthroughUpstream 返回先发 response.created（不构成客户端输出）后一直挂起的上游响应。
func newStalledPassthroughUpstream(t *testing.T) (*http.Response, *io.PipeWriter) {
	t.Helper()
	pr, pw := io.Pipe()
	go func() {
		_, _ = io.WriteString(pw, "event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_1\"}}\n\n")
	}()
	t.Cleanup(func() { _ = pw.Close() })
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
		Body:       pr,
	}, pw
}

func newWatchdogPassthroughTestContext() *gin.Context {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	return c
}

func TestOpenAIPassthroughStreamIdleTimeoutFailsOverBeforeOutput(t *testing.T) {
	svc := &OpenAIGatewayService{cfg: &config.Config{Gateway: config.GatewayConfig{StreamDataIntervalTimeout: 1}}}
	account := &Account{ID: 931, Platform: PlatformOpenAI, Type: AccountTypeOAuth}
	resp, _ := newStalledPassthroughUpstream(t)
	c := newWatchdogPassthroughTestContext()

	start := time.Now()
	result, err := svc.handleStreamingResponsePassthrough(context.Background(), resp, c, account, time.Now(), "gpt-5", "gpt-5")

	require.Error(t, err)
	require.NotNil(t, result)
	var failoverErr *UpstreamFailoverError
	require.True(t, errors.As(err, &failoverErr), "无输出时空闲超时应转为可换号错误: %v", err)
	require.Less(t, time.Since(start), 5*time.Second)
}

func TestOpenAIPassthroughStreamClientGoneBeforeOutputCancelsUpstream(t *testing.T) {
	svc := &OpenAIGatewayService{cfg: &config.Config{}}
	account := &Account{ID: 932, Platform: PlatformOpenAI, Type: AccountTypeOAuth}
	resp, pw := newStalledPassthroughUpstream(t)
	c := newWatchdogPassthroughTestContext()
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)

	start := time.Now()
	result, err := svc.handleStreamingResponsePassthrough(ctx, resp, c, account, time.Now(), "gpt-5", "gpt-5")

	require.Error(t, err)
	require.NotNil(t, result)
	require.Contains(t, err.Error(), string(openAIPassthroughStreamCutClientGone))
	var failoverErr *UpstreamFailoverError
	require.False(t, errors.As(err, &failoverErr), "客户端已断开不应触发换号重放")
	require.Less(t, time.Since(start), 5*time.Second)
	_, writeErr := io.WriteString(pw, "data: {}\n\n")
	require.ErrorIs(t, writeErr, io.ErrClosedPipe, "上游 body 应已被关闭")
}
