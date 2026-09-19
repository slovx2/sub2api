package service

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/stretchr/testify/require"
)

// 单次探测协议测试直接覆盖真实探测函数；重试和并发另由请求路径测试覆盖。
func (s *OpenAIGatewayService) probeCodexTicketForTest(ctx context.Context, account *Account, model string) {
	_, generation := s.codexTicketAccountScope(ctx)
	if s.checkCodexTicketRequestAccount(ctx, account, generation) != nil {
		return
	}
	_, _ = s.probeOpenAICodexTicketAttempt(ctx, account, model, s.codexTicketPolicy(ctx), s.openAICodexTicketConfig(), generation, 1)
}

func requestTicket(t *testing.T, s *OpenAIGatewayService, a *Account, model string) http.Header {
	t.Helper()
	headers := http.Header{}
	require.NoError(t, s.applyOpenAICodexTicket(context.Background(), a, model, headers))
	return headers
}

func waitTicketWaiters(t *testing.T, s *OpenAIGatewayService, id int64, model string, n int) {
	t.Helper()
	require.Eventually(t, func() bool {
		s.openaiCodexTicketLifecycleMu.Lock()
		defer s.openaiCodexTicketLifecycleMu.Unlock()
		work := s.openaiCodexTicketAccounts[id]
		return work != nil && work.calls[model] != nil && work.calls[model].waiters == n
	}, 3*time.Second, time.Millisecond)
}

func TestCodexTicketRequestsShareRetryRound(t *testing.T) {
	for _, success := range []bool{true, false} {
		t.Run(map[bool]string{true: "success", false: "exhausted"}[success], func(t *testing.T) {
			var attempts atomic.Int32
			started, release := make(chan struct{}), make(chan struct{})
			upstream := &codexTicketFuncUpstream{do: func(req *http.Request) (*http.Response, error) {
				n := attempts.Add(1)
				if n == 1 {
					close(started)
					select {
					case <-release:
					case <-req.Context().Done():
						return nil, req.Context().Err()
					}
				}
				if success && n == 3 {
					return codexTicketResponse(), nil
				}
				return nil, errors.New("probe failed")
			}}
			svc := ticketTestService(t, config.OpenAICodexTicketConfig{Enabled: true, HarvestProxyURL: "http://proxy:8080"}, upstream)
			account := ticketTestAccount(41)
			repo := &codexTicketRefreshRepo{accounts: []Account{*account}}
			svc.accountRepo = repo
			logs := &ticketLogMemoryRepo{}
			svc.codexTicketLogRepo = logs
			errs := make(chan error, 20)
			for i := 0; i < 20; i++ {
				go func() {
					errs <- svc.applyOpenAICodexTicket(context.Background(), account, "gpt-6-astra", http.Header{})
				}()
			}
			<-started
			waitTicketWaiters(t, svc, 41, "gpt-6-astra", 20)
			close(release)
			for i := 0; i < 20; i++ {
				err := <-errs
				if success {
					require.NoError(t, err)
				} else {
					var failover *UpstreamFailoverError
					require.ErrorAs(t, err, &failover)
					require.False(t, failover.RetryableOnSameAccount)
					require.True(t, failover.ShouldRetryNextAccount())
				}
			}
			require.Equal(t, int32(3), attempts.Load())
			page, _ := logs.List(context.Background(), CodexTicketLogFilter{})
			for i := 0; i < 3; i++ {
				require.Equal(t, i+1, page.Items[i].Attempt)
			}
			if success {
				require.Len(t, page.Items, 3)
				requestTicket(t, svc, account, "gpt-6-astra")
			} else {
				require.Len(t, page.Items, 4)
				require.Equal(t, "cooldown", page.Items[3].Kind)
				require.True(t, svc.isOpenAIAccountRequestRuntimeBlocked(account, "other-model", false), "旧快照也不能清除冷却")
				require.Error(t, svc.applyOpenAICodexTicket(context.Background(), account, "gpt-6-astra", http.Header{}))
				current, err := repo.GetByID(context.Background(), account.ID)
				require.NoError(t, err)
				require.WithinDuration(t, time.Now().Add(time.Hour), *current.TempUnschedulableUntil, 5*time.Second)
			}
			require.Equal(t, int32(3), attempts.Load())
		})
	}
}

func TestCodexTicketRequestsCancellation(t *testing.T) {
	started := make(chan struct{})
	finish := make(chan struct{})
	var calls atomic.Int32
	upstream := &codexTicketFuncUpstream{do: func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		close(started)
		select {
		case <-finish:
			return codexTicketResponse(), nil
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
	}}
	svc := ticketTestService(t, config.OpenAICodexTicketConfig{Enabled: true, HarvestProxyURL: "http://proxy:8080"}, upstream)
	a := ticketTestAccount(41)
	ctx, cancel := context.WithCancel(context.Background())
	first, second := make(chan error, 1), make(chan error, 1)
	go func() { first <- svc.applyOpenAICodexTicket(ctx, a, "gpt-6-astra", http.Header{}) }()
	<-started
	go func() { second <- svc.applyOpenAICodexTicket(context.Background(), a, "gpt-6-astra", http.Header{}) }()
	waitTicketWaiters(t, svc, 41, "gpt-6-astra", 2)
	cancel()
	require.ErrorIs(t, <-first, context.Canceled)
	close(finish)
	require.NoError(t, <-second)
	require.Equal(t, int32(1), calls.Load())
	require.False(t, svc.codexTicketCooldownActive(a))
}

func TestCodexTicketRequestsSerializeModels(t *testing.T) {
	var active, peak, calls atomic.Int32
	upstream := &codexTicketFuncUpstream{do: func(*http.Request) (*http.Response, error) {
		n := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
		}
		calls.Add(1)
		return codexTicketResponse(), nil
	}}
	svc := ticketTestService(t, config.OpenAICodexTicketConfig{Enabled: true, HarvestProxyURL: "http://proxy:8080"}, upstream)
	account := ticketTestAccount(41)
	account.Extra = map[string]any{"existing": true}
	svc.accountRepo = &codexTicketRefreshRepo{accounts: []Account{*account}}
	var wg sync.WaitGroup
	for _, model := range []string{"gpt-6-astra", "gpt-5.6-sol"} {
		wg.Add(1)
		go func(model string) { defer wg.Done(); requestTicket(t, svc, account, model) }(model)
	}
	wg.Wait()
	require.Equal(t, int32(1), peak.Load())
	require.Equal(t, int32(2), calls.Load())
	require.Equal(t, map[string]any{"existing": true}, account.Extra)
}
