package service

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"
)

func ticketFailureCount(s *OpenAIGatewayService, id int64, model string) int {
	state := s.codexTicketFailureState(id)
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.counts[model]
}

func TestCodexTicketFailuresModelIsolationAndReset(t *testing.T) {
	ctx := context.Background()
	failAstra, failSol := true, false
	var calls int
	svc, a := backgroundTicketService(t, &codexTicketFuncUpstream{do: func(req *http.Request) (*http.Response, error) {
		calls++
		body, err := io.ReadAll(req.Body)
		require.NoError(t, err)
		if (strings.Contains(string(body), "gpt-6-astra") && failAstra) || (strings.Contains(string(body), "gpt-5.6-sol") && failSol) {
			return nil, errors.New("private upstream error must not leak")
		}
		return codexTicketResponse(), nil
	}})
	svc.cfg.Gateway.OpenAICodexTicket.Models = []string{"gpt-6-astra", "gpt-5.6-sol"}
	setTicketPolicyForTest(svc, CodexTicketPolicy{3600, 600, 20, 3})
	svc.refreshOpenAICodexTickets(ctx)
	require.Equal(t, 2, calls, "首个模型失败不阻止其他模型")
	require.Equal(t, 1, ticketFailureCount(svc, a.ID, "gpt-6-astra"))
	require.Zero(t, ticketFailureCount(svc, a.ID, "gpt-5.6-sol"))
	failAstra, failSol = false, true
	svc.openaiCodexTickets.Delete(openAICodexTicketKey(a.ID, "gpt-5.6-sol"))
	svc.refreshOpenAICodexTickets(ctx)
	require.Zero(t, ticketFailureCount(svc, a.ID, "gpt-6-astra"), "本模型成功清零")
	require.Equal(t, 1, ticketFailureCount(svc, a.ID, "gpt-5.6-sol"))
	svc.refreshOpenAICodexTickets(ctx)
	require.Equal(t, 2, ticketFailureCount(svc, a.ID, "gpt-5.6-sol"))
	require.False(t, svc.codexTicketErrorActive(a))
	svc.refreshOpenAICodexTickets(ctx)
	require.True(t, svc.codexTicketErrorActive(a))
	current, err := svc.accountRepo.GetByID(ctx, a.ID)
	require.NoError(t, err)
	require.Equal(t, StatusError, current.Status)
	require.Contains(t, current.ErrorMessage, "model=gpt-5.6-sol consecutive_failures=3")
	require.NotContains(t, current.ErrorMessage, "private")
	require.False(t, current.Schedulable)
	require.True(t, svc.isOpenAIAccountRequestRuntimeBlocked(a, "other-model", false), "旧快照也不能放行")
	before := calls
	svc.refreshOpenAICodexTickets(ctx)
	require.Equal(t, before, calls)
	view, err := svc.CodexTicketOverview(ctx, 1, 20, true)
	require.NoError(t, err)
	require.Equal(t, 1, view.Accounts)
	require.Len(t, view.Items, 2, "错误账号仍可查询")
	require.Equal(t, 3, view.Items[1].ConsecutiveFailures)
	require.NotEmpty(t, view.Items[0].AccountError)
	// 重启清内存计数，但不会恢复数据库里的错误账号。
	restarted, _ := backgroundTicketService(t, svc.httpUpstream)
	restarted.accountRepo = svc.accountRepo
	restarted.refreshOpenAICodexTickets(ctx)
	require.Zero(t, ticketFailureCount(restarted, a.ID, "gpt-5.6-sol"))
	require.Equal(t, before, calls)
	recovery := &RateLimitService{accountRepo: svc.accountRepo, runtimeBlocker: svc}
	_, err = recovery.RecoverAccountAfterSuccessfulTest(ctx, a.ID)
	require.NoError(t, err)
	current, err = svc.accountRepo.GetByID(ctx, a.ID)
	require.NoError(t, err)
	require.Equal(t, StatusError, current.Status, "连通性测试成功不能恢复采票错误")
	_, err = recovery.RecoverAccountState(ctx, a.ID, AccountRecoveryOptions{Manual: true})
	require.NoError(t, err)
	require.Zero(t, ticketFailureCount(svc, a.ID, "gpt-5.6-sol"))
	current, err = svc.accountRepo.GetByID(ctx, a.ID)
	require.NoError(t, err)
	require.Equal(t, StatusActive, current.Status)
	require.False(t, current.Schedulable)
}

func TestCodexTicketFailuresPauseAndThresholdHotReload(t *testing.T) {
	ctx := context.Background()
	svc, a := backgroundTicketService(t, &codexTicketFuncUpstream{do: func(*http.Request) (*http.Response, error) { return nil, errors.New("failed") }})
	setTicketPolicyForTest(svc, CodexTicketPolicy{3600, 600, 20, 30})
	for i := 0; i < 3; i++ {
		svc.refreshOpenAICodexTickets(ctx)
	}
	require.Equal(t, 3, ticketFailureCount(svc, a.ID, "gpt-6-astra"))
	require.NoError(t, svc.accountRepo.SetSchedulable(ctx, a.ID, false))
	svc.refreshOpenAICodexTickets(ctx)
	require.Equal(t, 3, ticketFailureCount(svc, a.ID, "gpt-6-astra"))
	setTicketPolicyForTest(svc, CodexTicketPolicy{3600, 600, 1, 2})
	require.False(t, svc.codexTicketErrorActive(a), "降低阈值不立即标错")
	require.NoError(t, svc.accountRepo.SetSchedulable(ctx, a.ID, true))
	svc.refreshOpenAICodexTickets(ctx)
	require.Equal(t, 4, ticketFailureCount(svc, a.ID, "gpt-6-astra"))
	require.True(t, svc.codexTicketErrorActive(a))
}

func TestCodexTicketCycleWaitsAfterCompletionAndUsesSnapshot(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int32
		svc, _ := backgroundTicketService(t, &codexTicketFuncUpstream{do: func(*http.Request) (*http.Response, error) {
			calls.Add(1)
			time.Sleep(5 * time.Second)
			return nil, errors.New("failed")
		}})
		setTicketPolicyForTest(svc, CodexTicketPolicy{3600, 600, 20, 30})
		svc.StartOpenAICodexTicketHarvester()
		defer svc.StopOpenAICodexTicketRequests()
		synctest.Wait()
		require.Equal(t, int32(1), calls.Load())
		setTicketPolicyForTest(svc, CodexTicketPolicy{3600, 600, 2, 30})
		time.Sleep(24 * time.Second)
		synctest.Wait()
		require.Equal(t, int32(1), calls.Load(), "本轮仍使用20秒间隔快照")
		time.Sleep(time.Second)
		synctest.Wait()
		require.Equal(t, int32(2), calls.Load())
		time.Sleep(7 * time.Second)
		synctest.Wait()
		require.Equal(t, int32(3), calls.Load(), "后续轮次使用新间隔")
	})
}
