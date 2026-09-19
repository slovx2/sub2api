package service

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

type ticketHTTPProxyRecorder struct {
	HTTPUpstream
	mu      sync.Mutex
	proxies []string
	started chan struct{}
	release chan struct{}
}

func (u *ticketHTTPProxyRecorder) Do(req *http.Request, proxy string, _ int64, _ int) (*http.Response, error) {
	u.mu.Lock()
	u.proxies = append(u.proxies, proxy)
	u.mu.Unlock()
	if HTTPUpstreamProfileFromContext(req.Context()) == HTTPUpstreamProfileOpenAIHarvest {
		close(u.started)
		select {
		case <-u.release:
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
		return codexTicketResponse(), nil
	}
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
}

func TestCodexTicketHTTPRequestWaitsAndKeepsBusinessProxy(t *testing.T) {
	upstream := &ticketHTTPProxyRecorder{started: make(chan struct{}), release: make(chan struct{})}
	svc := ticketTestService(t, config.OpenAICodexTicketConfig{Enabled: true, HarvestProxyURL: "http://harvest.example:8080"}, upstream)
	a := ticketTestAccount(41)
	a.Proxy = &Proxy{ID: 7, Protocol: "http", Host: "business.example", Port: 8080}
	a.ProxyID = &a.Proxy.ID
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	original := []byte(`{"model":"gpt-6-astra","stream":false,"input":"original request"}`)
	built := make(chan *http.Request, 1)
	errs := make(chan error, 1)
	go func() {
		req, err := svc.buildUpstreamRequest(context.Background(), c, a, original, "tok", false, "", false)
		built <- req
		errs <- err
	}()
	<-upstream.started
	select {
	case <-built:
		t.Fatal("采票完成前原请求已经继续")
	default:
	}
	close(upstream.release)
	req := <-built
	require.NoError(t, <-errs)
	require.Len(t, req.Header.Get(openAICodexTurnStateHeader), 292)
	body, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	require.JSONEq(t, string(original), string(body))
	req.Body = io.NopCloser(strings.NewReader(string(body)))
	resp, err := svc.doOpenAIUpstream(req, a.Proxy.URL(), a)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	upstream.mu.Lock()
	defer upstream.mu.Unlock()
	require.Equal(t, []string{"http://harvest.example:8080", "http://business.example:8080"}, upstream.proxies)
}

func TestCodexTicketHTTPRequestHonorsOriginalCancellation(t *testing.T) {
	svc := ticketTestService(t, config.OpenAICodexTicketConfig{Enabled: true}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil).WithContext(ctx)
	err := svc.applyOpenAICodexTicketForRequest(context.WithoutCancel(ctx), c, ticketTestAccount(41), "gpt-6-astra", http.Header{})
	require.ErrorIs(t, err, context.Canceled)
	require.False(t, svc.codexTicketCooldownActive(ticketTestAccount(41)))
}
