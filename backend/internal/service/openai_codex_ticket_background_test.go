package service

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/stretchr/testify/require"
)

// 后台热更新测试会并发读取设置，测试仓储也须提供同步保护。
type backgroundTicketSettingRepo struct {
	SettingRepository
	mu     sync.Mutex
	values map[string]string
}

func (r *backgroundTicketSettingRepo) GetValue(_ context.Context, key string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	value, ok := r.values[key]
	if !ok {
		return "", ErrSettingNotFound
	}
	return value, nil
}

func (r *backgroundTicketSettingRepo) set(key, value string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.values[key] = value
}

func backgroundTicketService(t *testing.T, upstream HTTPUpstream) (*OpenAIGatewayService, *Account) {
	t.Helper()
	svc := ticketTestService(t, config.OpenAICodexTicketConfig{
		Enabled: true, HarvestProxyURL: "http://proxy:8080", Models: []string{"gpt-6-astra"},
	}, upstream)
	a := ticketTestAccount(41)
	svc.accountRepo = &codexTicketRefreshRepo{accounts: []Account{*a}}
	return svc, a
}

func TestCodexTicketBackgroundStartupRefreshAndStop(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int32
		svc, _ := backgroundTicketService(t, &codexTicketFuncUpstream{do: func(*http.Request) (*http.Response, error) {
			calls.Add(1)
			return codexTicketResponse(), nil
		}})
		setTicketPolicyForTest(svc, CodexTicketPolicy{60, 12, 3, 60})
		svc.StartOpenAICodexTicketHarvester()
		defer svc.StopOpenAICodexTicketRequests()
		svc.StartOpenAICodexTicketHarvester()
		synctest.Wait()
		require.Equal(t, int32(1), calls.Load(), "无业务请求也会启动预采，多次启动不能重复采票")
		time.Sleep(48 * time.Second)
		synctest.Wait()
		require.Equal(t, int32(1), calls.Load(), "剩余有效期等于提前量时不刷新")
		time.Sleep(codexTicketBackgroundInterval)
		synctest.Wait()
		require.Equal(t, int32(2), calls.Load(), "进入提前量后自动刷新")
		svc.StopOpenAICodexTicketRequests()
		svc.StartOpenAICodexTicketHarvester()
		time.Sleep(time.Minute)
		synctest.Wait()
		require.Equal(t, int32(2), calls.Load(), "停止后不能重启或继续采票")
	})
}

func TestCodexTicketBackgroundCooldownAutomaticallyRecovers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int32
		svc, a := backgroundTicketService(t, &codexTicketFuncUpstream{do: func(*http.Request) (*http.Response, error) {
			if calls.Add(1) <= 3 {
				return nil, errors.New("probe failed")
			}
			return codexTicketResponse(), nil
		}})
		setTicketPolicyForTest(svc, CodexTicketPolicy{3600, 600, 3, 60})
		svc.StartOpenAICodexTicketHarvester()
		defer svc.StopOpenAICodexTicketRequests()
		synctest.Wait()
		require.Equal(t, int32(3), calls.Load())
		require.True(t, svc.codexTicketCooldownActive(a))
		time.Sleep(54 * time.Second)
		synctest.Wait()
		require.Equal(t, int32(3), calls.Load(), "冷却中不请求采票")
		time.Sleep(codexTicketBackgroundInterval)
		synctest.Wait()
		require.Equal(t, int32(4), calls.Load(), "冷却结束无需业务请求即可重试")
		require.True(t, svc.lookupOpenAICodexTicket(a, "gpt-6-astra").valid(time.Now(), 292))
	})
}

func TestCodexTicketBackgroundSharesWithRequest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int32
		finish := make(chan struct{})
		svc, a := backgroundTicketService(t, &codexTicketFuncUpstream{do: func(req *http.Request) (*http.Response, error) {
			calls.Add(1)
			select {
			case <-finish:
				return codexTicketResponse(), nil
			case <-req.Context().Done():
				return nil, req.Context().Err()
			}
		}})
		svc.StartOpenAICodexTicketHarvester()
		defer svc.StopOpenAICodexTicketRequests()
		synctest.Wait()
		result := make(chan error, 1)
		headers := http.Header{}
		go func() { result <- svc.applyOpenAICodexTicket(context.Background(), a, "gpt-6-astra", headers) }()
		synctest.Wait()
		svc.openaiCodexTicketLifecycleMu.Lock()
		waiters := svc.openaiCodexTicketAccounts[a.ID].calls["gpt-6-astra"].waiters
		svc.openaiCodexTicketLifecycleMu.Unlock()
		require.Equal(t, 2, waiters)
		close(finish)
		require.NoError(t, <-result)
		require.Len(t, headers.Get(openAICodexTurnStateHeader), 292)
		require.Equal(t, int32(1), calls.Load())
	})
}

func TestCodexTicketBackgroundStopCancelsInFlight(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int32
		svc, a := backgroundTicketService(t, &codexTicketFuncUpstream{do: func(req *http.Request) (*http.Response, error) {
			calls.Add(1)
			<-req.Context().Done()
			return nil, req.Context().Err()
		}})
		svc.StartOpenAICodexTicketHarvester()
		synctest.Wait()
		svc.StopOpenAICodexTicketRequests()
		require.Equal(t, int32(1), calls.Load())
		require.False(t, svc.codexTicketCooldownActive(a), "正常关闭不能触发失败冷却")
	})
}

func TestCodexTicketBackgroundEnableAndScopeHotReload(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int32
		svc, a := backgroundTicketService(t, &codexTicketFuncUpstream{do: func(*http.Request) (*http.Response, error) {
			calls.Add(1)
			return codexTicketResponse(), nil
		}})
		b, disabled, shadow := ticketTestAccount(42), ticketTestAccount(43), ticketTestAccount(44)
		disabled.Status = StatusError
		shadow.ParentAccountID = &a.ID
		svc.accountRepo = &codexTicketRefreshRepo{accounts: []Account{*a, *b, *disabled, *shadow}}
		repo := &backgroundTicketSettingRepo{values: map[string]string{
			SettingKeyOpenAICodexTicketEnabled: "false", SettingKeyOpenAICodexTicketAccountIDs: "[41,43,44]",
		}}
		svc.settingService = NewSettingService(repo, svc.cfg)
		svc.StartOpenAICodexTicketHarvester()
		defer svc.StopOpenAICodexTicketRequests()
		synctest.Wait()
		require.Zero(t, calls.Load(), "开关关闭时不采票")
		repo.set(SettingKeyOpenAICodexTicketEnabled, "true")
		svc.settingService.InvalidateOpenAICodexTicketEnabledCache()
		time.Sleep(codexTicketBackgroundInterval)
		synctest.Wait()
		require.Equal(t, int32(1), calls.Load(), "热开启后只采选中的有效非影子账号")
		require.NotNil(t, svc.lookupOpenAICodexTicket(a, "gpt-6-astra"))
		require.Nil(t, svc.lookupOpenAICodexTicket(b, "gpt-6-astra"))
		repo.set(SettingKeyOpenAICodexTicketAccountIDs, "[42]")
		svc.settingService.InvalidateOpenAICodexTicketAccountsCache()
		time.Sleep(codexTicketBackgroundInterval)
		synctest.Wait()
		require.Equal(t, int32(2), calls.Load())
		require.NotNil(t, svc.lookupOpenAICodexTicket(b, "gpt-6-astra"))
		repo.set(SettingKeyOpenAICodexTicketEnabled, "false")
		svc.settingService.InvalidateOpenAICodexTicketEnabledCache()
		time.Sleep(2 * time.Hour)
		synctest.Wait()
		require.Equal(t, int32(2), calls.Load(), "热关闭后不再刷新")
	})
}

func TestCodexTicketBackgroundScopeChangeDiscardsInFlight(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		finish := make(chan struct{})
		svc, a := backgroundTicketService(t, &codexTicketFuncUpstream{do: func(req *http.Request) (*http.Response, error) {
			select {
			case <-finish:
				return codexTicketResponse(), nil
			case <-req.Context().Done():
				return nil, req.Context().Err()
			}
		}})
		repo := &backgroundTicketSettingRepo{values: map[string]string{
			SettingKeyOpenAICodexTicketAccountIDs: "[41]",
		}}
		svc.settingService = NewSettingService(repo, svc.cfg)
		svc.StartOpenAICodexTicketHarvester()
		defer svc.StopOpenAICodexTicketRequests()
		synctest.Wait()
		repo.set(SettingKeyOpenAICodexTicketAccountIDs, "[99999]")
		svc.settingService.InvalidateOpenAICodexTicketAccountsCache()
		close(finish)
		synctest.Wait()
		require.Nil(t, svc.lookupOpenAICodexTicket(a, "gpt-6-astra"))
		require.False(t, svc.codexTicketCooldownActive(a))
	})
}

func TestCodexTicketBackgroundNoProxyDoesNotCooldown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int32
		svc, a := backgroundTicketService(t, &codexTicketFuncUpstream{do: func(*http.Request) (*http.Response, error) {
			calls.Add(1)
			return codexTicketResponse(), nil
		}})
		svc.cfg.Gateway.OpenAICodexTicket.HarvestProxyURL = ""
		svc.StartOpenAICodexTicketHarvester()
		defer svc.StopOpenAICodexTicketRequests()
		time.Sleep(time.Minute)
		synctest.Wait()
		require.Zero(t, calls.Load())
		require.False(t, svc.codexTicketCooldownActive(a))
	})
}
