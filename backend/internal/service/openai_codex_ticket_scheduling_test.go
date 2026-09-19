package service

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"
)

func setTicketSchedulingForTest(repo *codexTicketRefreshRepo, enabled bool) {
	repo.mu.Lock()
	defer repo.mu.Unlock()
	repo.accounts[0].Schedulable = enabled
}

func ticketSchedulingRepo(t *testing.T, svc *OpenAIGatewayService) *codexTicketRefreshRepo {
	t.Helper()
	repo, ok := svc.accountRepo.(*codexTicketRefreshRepo)
	require.True(t, ok)
	return repo
}

func TestCodexTicketBackgroundSchedulingToggle(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int32
		svc, a := backgroundTicketService(t, &codexTicketFuncUpstream{do: func(*http.Request) (*http.Response, error) {
			calls.Add(1)
			return codexTicketResponse(), nil
		}})
		repo := ticketSchedulingRepo(t, svc)
		setTicketSchedulingForTest(repo, false)
		svc.StartOpenAICodexTicketHarvester()
		defer svc.StopOpenAICodexTicketRequests()
		time.Sleep(time.Minute)
		synctest.Wait()
		require.Zero(t, calls.Load(), "关闭调度的账号不能自动采票")
		require.False(t, svc.codexTicketCooldownActive(a))
		setTicketSchedulingForTest(repo, true)
		time.Sleep(codexTicketBackgroundInterval)
		synctest.Wait()
		require.Equal(t, int32(1), calls.Load(), "开启调度后下一轮自动采票")
		setTicketSchedulingForTest(repo, false)
		time.Sleep(2 * time.Hour)
		synctest.Wait()
		require.Equal(t, int32(1), calls.Load(), "关闭期间票据过期也不能刷新")
		setTicketSchedulingForTest(repo, true)
		time.Sleep(codexTicketBackgroundInterval)
		synctest.Wait()
		require.Equal(t, int32(2), calls.Load(), "再次开启后能恢复刷新")
	})
}

func TestCodexTicketSchedulingDisabledDuringProbe(t *testing.T) {
	for _, success := range []bool{true, false} {
		t.Run(map[bool]string{true: "丢弃成功结果", false: "不再重试且不冷却"}[success], func(t *testing.T) {
			var calls atomic.Int32
			var repo *codexTicketRefreshRepo
			svc, a := backgroundTicketService(t, &codexTicketFuncUpstream{do: func(*http.Request) (*http.Response, error) {
				calls.Add(1)
				setTicketSchedulingForTest(repo, false)
				if success {
					return codexTicketResponse(), nil
				}
				return nil, errors.New("probe failed")
			}})
			repo = ticketSchedulingRepo(t, svc)
			svc.refreshOpenAICodexTickets(context.Background())
			require.Equal(t, int32(1), calls.Load())
			require.Nil(t, svc.lookupOpenAICodexTicket(a, "gpt-6-astra"))
			require.False(t, svc.codexTicketCooldownActive(a))
		})
	}
}

func TestCodexTicketRequestCannotHarvestWithDisabledScheduling(t *testing.T) {
	var calls atomic.Int32
	svc, a := backgroundTicketService(t, &codexTicketFuncUpstream{do: func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return codexTicketResponse(), nil
	}})
	setTicketSchedulingForTest(ticketSchedulingRepo(t, svc), false)
	// 旧调度快照仍认为可调度，探测前必须重新读取账号真值。
	require.Error(t, svc.applyOpenAICodexTicket(context.Background(), a, "gpt-6-astra", http.Header{}))
	a.Schedulable = false
	require.Error(t, svc.applyOpenAICodexTicket(context.Background(), a, "gpt-6-astra", http.Header{}))
	require.Zero(t, calls.Load())
	require.False(t, svc.codexTicketCooldownActive(a))
}

func TestCodexTicketSchedulingDisabledDuringPersistence(t *testing.T) {
	svc, a := backgroundTicketService(t, &codexTicketFuncUpstream{do: func(*http.Request) (*http.Response, error) {
		return codexTicketResponse(), nil
	}})
	base := ticketSchedulingRepo(t, svc)
	repo := &ticketCommitScopeRepo{codexTicketRefreshRepo: base, onWrite: func() {
		setTicketSchedulingForTest(base, false)
	}}
	svc.accountRepo = repo
	svc.refreshOpenAICodexTickets(context.Background())
	require.Nil(t, svc.lookupOpenAICodexTicket(a, "gpt-6-astra"))
	require.Nil(t, repo.updates[openAICodexTicketExtraKey("gpt-6-astra")], "写库期间关闭调度，刚写入的结果也须丢弃")
	require.False(t, svc.codexTicketCooldownActive(a))
}
