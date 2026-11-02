package service

import (
	"context"
	"strconv"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/claude"
	"github.com/stretchr/testify/require"
)

type anthropicDeepseekGroupRepo struct {
	GroupRepository
}

func (anthropicDeepseekGroupRepo) GetByIDLite(_ context.Context, id int64) (*Group, error) {
	return &Group{ID: id, Platform: PlatformAnthropic}, nil
}

func TestGetAvailableModels_AnthropicDeepseek(t *testing.T) {
	groupID := int64(71)
	for _, mapped := range []bool{false, true} {
		t.Run(map[bool]string{false: "默认模型", true: "显式映射"}[mapped], func(t *testing.T) {
			deepseek := Account{ID: 2, Platform: PlatformDeepseek, Type: AccountTypeAPIKey}
			if mapped {
				deepseek.Credentials = map[string]any{"model_mapping": map[string]any{
					"deepseek-flash": "deepseek-flash",
					"custom-alias":   "deepseek-flash",
					"claude-fake":    "deepseek-flash",
				}}
			}
			repo := &modelsListAccountRepoStub{byGroup: map[int64][]Account{groupID: {
				{ID: 1, Platform: PlatformAnthropic, Type: AccountTypeOAuth},
				deepseek,
				{ID: 3, Platform: PlatformOpenAI, Credentials: map[string]any{"model_mapping": map[string]any{"gpt-5.5": "gpt-5.5"}}},
			}}}
			svc := &GatewayService{accountRepo: repo}
			models := svc.GetAvailableModels(context.Background(), &groupID, PlatformAnthropic)
			require.Contains(t, models, "deepseek-flash")
			for _, model := range claude.DefaultModels {
				require.Contains(t, models, model.ID)
			}
			require.NotContains(t, models, "custom-alias")
			require.NotContains(t, models, "claude-fake")
			require.NotContains(t, models, "gpt-5.5")
			admin := &adminServiceImpl{
				accountRepo: repo,
				groupRepo:   anthropicDeepseekGroupRepo{},
			}
			candidates, err := admin.GetGroupModelsListCandidates(context.Background(), groupID, PlatformAnthropic)
			require.NoError(t, err)
			require.Contains(t, candidates, "deepseek-flash")
			require.NotContains(t, candidates, "custom-alias")
			require.NotContains(t, candidates, "claude-fake")
			require.NotContains(t, candidates, "gpt-5.5")
			if mapped {
				require.NotContains(t, models, "deepseek-v4-pro")
			}
		})
	}
}

func TestAnthropicDeepseekSchedulingStaysInGroup(t *testing.T) {
	groupID := int64(71)
	deepseek := compositeMultiPlatformTestAccount(712, PlatformDeepseek, 50, groupID, nil)
	claudeAccount := compositeMultiPlatformTestAccount(711, PlatformAnthropic, 1, groupID, nil)
	otherGroupAccount := compositeMultiPlatformTestAccount(713, PlatformDeepseek, 1, 43, nil)
	for _, advanced := range []string{"true", "false"} {
		for _, boundAccount := range []Account{claudeAccount, otherGroupAccount, deepseek} {
			t.Run(advanced+"/"+boundAccount.Platform+"/"+strconv.FormatInt(boundAccount.ID, 10), func(t *testing.T) {
				resetOpenAIAdvancedSchedulerSettingCacheForTest()
				repo := schedulerGroupAwareOpenAIAccountRepo{schedulerTestOpenAIAccountRepo{accounts: []Account{
					claudeAccount, otherGroupAccount, deepseek,
				}}}
				svc := &OpenAIGatewayService{
					accountRepo:        repo,
					cache:              &schedulerTestGatewayCache{sessionBindings: map[string]int64{"openai:sticky": boundAccount.ID}},
					cfg:                &config.Config{},
					rateLimitService:   newOpenAIAdvancedSchedulerRateLimitService(advanced),
					concurrencyService: NewConcurrencyService(schedulerTestConcurrencyCache{}),
				}
				ctx := WithResolvedTargetPlatform(context.Background(), PlatformDeepseek)
				selection, _, err := svc.SelectAccountWithSchedulerForCapability(ctx, &groupID, "", "sticky", "deepseek-flash", nil,
					OpenAIUpstreamTransportAny, OpenAIEndpointCapabilityChatCompletions, false, false, true, PlatformDeepseek)
				require.NoError(t, err)
				require.NotNil(t, selection)
				require.Equal(t, deepseek.ID, selection.Account.ID)
				if selection.ReleaseFunc != nil {
					selection.ReleaseFunc()
				}
				// 该分组的唯一 DeepSeek 账号失效时，不借用其他分组的账号。
				_, _, err = svc.SelectAccountWithSchedulerForCapability(ctx, &groupID, "", "", "deepseek-flash", map[int64]struct{}{deepseek.ID: {}},
					OpenAIUpstreamTransportAny, OpenAIEndpointCapabilityChatCompletions, false, false, true, PlatformDeepseek)
				require.Error(t, err)
			})
		}
	}
}
