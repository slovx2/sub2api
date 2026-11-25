package service

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"syscall"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/tlsfingerprint"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

type transportCooldownWrite struct {
	accountID int64
	until     time.Time
	reason    string
}

type transportCooldownRepo struct {
	schedulerTestOpenAIAccountRepo
	pauses     []transportCooldownWrite
	accountErr string
}

func (r *transportCooldownRepo) SetTempUnschedulable(_ context.Context, id int64, until time.Time, reason string) error {
	r.pauses = append(r.pauses, transportCooldownWrite{id, until, reason})
	return nil
}

func (r *transportCooldownRepo) SetError(_ context.Context, _ int64, message string) error {
	r.accountErr = message
	return nil
}

type transportCooldownUpstream struct {
	err  error
	resp *http.Response
}

func (u *transportCooldownUpstream) Do(*http.Request, string, int64, int) (*http.Response, error) {
	return u.resp, u.err
}

func (u *transportCooldownUpstream) DoWithTLS(*http.Request, string, int64, int, *tlsfingerprint.Profile) (*http.Response, error) {
	return u.resp, u.err
}

// 复现 11 月 24 日分组 49 的 DeepSeek Chat 请求路线，涵盖有无备选账号。
func TestDeepSeekChatTransportCooldown(t *testing.T) {
	const model = "deepseek-flash"
	for _, tc := range []struct {
		name   string
		err    error
		backup bool
	}{
		{name: "唯一账号遇到 ENETUNREACH", err: &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ENETUNREACH}},
		{name: "有备选账号时仍不暂停", err: errors.New("dial tcp 192.0.2.10:443: connect: network is unreachable"), backup: true},
		{name: "DNS 未找到不暂停", err: &net.DNSError{Err: "no such host", Name: "proxy.example.com", IsNotFound: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			groupID := int64(49)
			ctx := WithCompositeRouteDecision(context.Background(), CompositeRouteDecision{
				Matched: true, Source: CompositeRouteSourceAccount, GroupID: groupID,
				PublicModel: model, UpstreamModel: model, TargetPlatform: PlatformDeepseek,
			})
			account := Account{
				ID: 387, GroupIDs: []int64{groupID}, Platform: PlatformDeepseek, Type: AccountTypeAPIKey,
				Status: StatusActive, Schedulable: true, Priority: 1, Concurrency: 1,
				Credentials: map[string]any{"api_key": "test-key", "base_url": "https://example.com", "model_mapping": map[string]any{model: model}},
			}
			repo := &transportCooldownRepo{schedulerTestOpenAIAccountRepo: schedulerTestOpenAIAccountRepo{accounts: []Account{account}}}
			if tc.backup {
				backup := account
				backup.ID, backup.Priority = 376, 3
				repo.accounts = append(repo.accounts, backup)
			}
			cfg := &config.Config{}
			rateLimit := &RateLimitService{cfg: cfg, accountRepo: repo}
			svc := &OpenAIGatewayService{cfg: cfg, accountRepo: repo, rateLimitService: rateLimit,
				httpUpstream: &transportCooldownUpstream{err: tc.err}}
			selection, _, err := svc.SelectAccountWithSchedulerForCapability(ctx, &groupID, "", "", model, nil,
				OpenAIUpstreamTransportAny, OpenAIEndpointCapabilityChatCompletions, false, false, false, PlatformDeepseek)
			require.NoError(t, err)
			require.Equal(t, account.ID, selection.Account.ID)
			c := newTransportCooldownContext(ctx)
			_, err = svc.ForwardAsChatCompletions(ctx, c, selection.Account,
				[]byte(`{"model":"deepseek-flash","messages":[{"role":"user","content":"ping"}]}`), "", "")
			var failover *UpstreamFailoverError
			require.ErrorAs(t, err, &failover)
			require.Equal(t, http.StatusBadGateway, failover.StatusCode)
			require.Empty(t, repo.pauses)
			require.Empty(t, repo.accountErr)
		})
	}
}

func newTransportCooldownContext(ctx context.Context) *gin.Context {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil).WithContext(ctx)
	return c
}

func TestTransportNetworkFailureStreak(t *testing.T) {
	for _, tc := range []struct {
		platform  string
		threshold int
		cooldown  time.Duration
	}{
		{platform: PlatformOpenAI, threshold: 3, cooldown: time.Minute},
		{platform: PlatformAnthropic, threshold: 3, cooldown: time.Minute},
		{platform: PlatformGemini, threshold: 2, cooldown: 45 * time.Second},
	} {
		t.Run(tc.platform, func(t *testing.T) {
			ctx := context.Background()
			repo := &transportCooldownRepo{}
			cfg := &config.Config{}
			if tc.platform == PlatformGemini {
				cfg.Gateway.Scheduling.TransportNetworkFailureThreshold = tc.threshold
				cfg.Gateway.Scheduling.TransportNetworkFailureCooldown = tc.cooldown
			}
			rateLimit := &RateLimitService{cfg: cfg, accountRepo: repo}
			account := &Account{ID: 387, Platform: tc.platform, Type: AccountTypeAPIKey}
			fake := &transportCooldownUpstream{}
			transport := withTransportRecovery(fake, rateLimit)
			c := newTransportCooldownContext(ctx)

			openAI := &OpenAIGatewayService{rateLimitService: rateLimit, accountRepo: repo, httpUpstream: transport}
			anthropic := &GatewayService{rateLimitService: rateLimit, accountRepo: repo, httpUpstream: transport}
			gemini := &GeminiMessagesCompatService{rateLimitService: rateLimit, accountRepo: repo, httpUpstream: transport}
			attempt := func(id int64, response *http.Response, dialErr error) error {
				t.Helper()
				fake.resp, fake.err = response, dialErr
				attemptAccount := *account
				attemptAccount.ID = id
				switch tc.platform {
				case PlatformOpenAI:
					_, err := openAI.doOpenAIUpstream(c.Request, "", &attemptAccount)
					if err != nil {
						return openAI.handleOpenAIUpstreamTransportError(ctx, c, &attemptAccount, err, false)
					}
				case PlatformAnthropic:
					_, err := anthropic.httpUpstream.DoWithTLS(c.Request, "", id, 1, nil)
					if err != nil {
						return anthropic.handleUpstreamTransportError(ctx, c, &attemptAccount, err, OpsUpstreamErrorEvent{})
					}
				case PlatformGemini:
					_, err := gemini.httpUpstream.Do(c.Request, "", id, 1)
					if err != nil {
						return gemini.handleUpstreamTransportError(ctx, c, &attemptAccount, err)
					}
				}
				return nil
			}
			fail := func() {
				t.Helper()
				var failover *UpstreamFailoverError
				require.ErrorAs(t, attempt(account.ID, nil, syscall.ECONNREFUSED), &failover)
				require.Equal(t, http.StatusBadGateway, failover.StatusCode)
			}
			for range tc.threshold - 1 {
				fail()
				require.Empty(t, repo.pauses)
			}
			require.False(t, openAI.isOpenAIAccountRuntimeBlocked(account))

			// 同一账号成功会清零；新的连续失败必须重新达到阈值。
			require.NoError(t, attempt(account.ID, &http.Response{StatusCode: http.StatusOK}, nil))
			for range tc.threshold - 1 {
				fail()
				require.Empty(t, repo.pauses)
			}
			require.NoError(t, attempt(account.ID+1, &http.Response{StatusCode: http.StatusOK}, nil))
			before := time.Now()
			fail()
			require.Len(t, repo.pauses, 1)
			require.Equal(t, account.ID, repo.pauses[0].accountID)
			require.WithinDuration(t, before.Add(tc.cooldown), repo.pauses[0].until, time.Second)
			require.Empty(t, repo.accountErr)
			if tc.platform == PlatformOpenAI {
				require.True(t, openAI.isOpenAIAccountRuntimeBlocked(account))
			}

			// 同一批在途失败不会不断延长已经写入的冷却。
			fail()
			require.Len(t, repo.pauses, 1)
		})
	}
}

func TestTransportCooldownKeepsHTTPAccountErrors(t *testing.T) {
	for _, tc := range []struct {
		status int
		marker string
	}{
		{status: http.StatusUnauthorized, marker: "Authentication failed (401)"},
		{status: http.StatusForbidden, marker: "Access forbidden (403)"},
	} {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			cfg := &config.Config{}
			repo := &transportCooldownRepo{}
			rateLimit := &RateLimitService{cfg: cfg, accountRepo: repo}
			account := &Account{ID: 387, Platform: PlatformGemini, Type: AccountTypeAPIKey}
			shouldStop := rateLimit.HandleUpstreamError(context.Background(), account, tc.status, nil,
				[]byte(`{"error":{"message":"credential rejected"}}`))
			require.True(t, shouldStop)
			require.Contains(t, repo.accountErr, tc.marker)
			require.Empty(t, repo.pauses)
		})
	}
}
