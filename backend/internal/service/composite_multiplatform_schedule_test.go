package service

import (
	"context"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/stretchr/testify/require"
)

func compositeMultiPlatformTestAccount(id int64, platform string, priority int, groupID int64, mapping map[string]any) Account {
	credentials := map[string]any{"api_key": "sk-test"}
	if mapping != nil {
		credentials["model_mapping"] = mapping
	}
	return Account{
		ID: id, Platform: platform, Type: AccountTypeAPIKey,
		Status: StatusActive, Schedulable: true, Concurrency: 1, Priority: priority,
		GroupIDs:    []int64{groupID},
		Credentials: credentials,
	}
}

// 多协议供应商同时认领模型时，按 composite 优先级给出候选集合并按选中账号重绑目标平台。
func TestCompositeMultiPlatformContextHelpers(t *testing.T) {
	groupID := int64(7)
	repo := &compositeOwnershipAccountRepo{accounts: []Account{
		{ID: 1, Platform: PlatformOpenCodeGo, Credentials: map[string]any{"model_mapping": map[string]any{"deepseek-flash": "deepseek-v4.1-flash"}}},
		{ID: 2, Platform: PlatformDeepseek, Credentials: map[string]any{"model_mapping": map[string]any{"deepseek-flash": "deepseek-flash"}}},
	}}
	ownership, err := (&GatewayService{accountRepo: repo}).resolveCompositeModelOwnership(context.Background(), groupID, "deepseek-flash")
	require.NoError(t, err)
	require.Equal(t, CompositeModelOwnership{Ambiguous: true, Platforms: []string{PlatformDeepseek, PlatformOpenCodeGo}}, ownership)

	ctx := WithCompositeRouteDecision(context.Background(), CompositeRouteDecision{
		Matched: true, Source: CompositeRouteSourceAccount, PublicModel: "deepseek-flash",
		TargetPlatform: PlatformDeepseek, UpstreamModel: "deepseek-flash",
		CandidatePlatforms: ownership.Platforms,
	})
	candidates, ok := CompositeCandidatePlatformsFromContext(ctx)
	require.True(t, ok)
	require.Equal(t, []string{PlatformDeepseek, PlatformOpenCodeGo}, candidates)

	require.True(t, openAIRequestPlatformMatches(ctx, PlatformOpenCodeGo, PlatformDeepseek))
	require.True(t, openAIRequestPlatformMatches(ctx, PlatformDeepseek, PlatformOpenCodeGo))
	require.False(t, openAIRequestPlatformMatches(ctx, PlatformKimi, PlatformDeepseek))
	require.False(t, openAIRequestPlatformMatches(ctx, PlatformOpenCodeGo, PlatformKimi))
	require.False(t, openAIRequestPlatformMatches(context.Background(), PlatformOpenCodeGo, PlatformDeepseek))

	rebound := RebindCompositeSelectedPlatform(ctx, PlatformOpenCodeGo)
	platform, ok := ResolvedTargetPlatformFromContext(rebound)
	require.True(t, ok)
	require.Equal(t, PlatformOpenCodeGo, platform)
	// 候选集合保留，failover 重新选号仍可跨平台。
	_, ok = CompositeCandidatePlatformsFromContext(rebound)
	require.True(t, ok)

	unchanged := RebindCompositeSelectedPlatform(ctx, PlatformKimi)
	platform, _ = ResolvedTargetPlatformFromContext(unchanged)
	require.Equal(t, PlatformDeepseek, platform)

	single := WithCompositeRouteDecision(context.Background(), CompositeRouteDecision{Matched: true, TargetPlatform: PlatformDeepseek})
	_, ok = CompositeCandidatePlatformsFromContext(single)
	require.False(t, ok)
	platform, _ = ResolvedTargetPlatformFromContext(RebindCompositeSelectedPlatform(single, PlatformOpenCodeGo))
	require.Equal(t, PlatformDeepseek, platform)
}

func TestCompositePlatformsMergeable(t *testing.T) {
	require.True(t, compositePlatformsMergeable([]string{PlatformDeepseek, PlatformOpenCodeGo}))
	require.True(t, compositePlatformsMergeable([]string{PlatformKimi, PlatformZhipu, PlatformMiniMax}))
	require.False(t, compositePlatformsMergeable([]string{PlatformDeepseek}))
	require.False(t, compositePlatformsMergeable([]string{PlatformAnthropic, PlatformDeepseek}))
	require.False(t, compositePlatformsMergeable([]string{PlatformOpenAI, PlatformDeepseek}))
	require.False(t, compositePlatformsMergeable([]string{PlatformGrok, PlatformOpenCodeGo}))
}

// 高级调度器与旧调度器都应在候选平台的认领账号间按优先级选号，排除未认领账号。
func TestOpenAIGatewayService_SelectAccountWithScheduler_CompositeMultiPlatformMergesOwners(t *testing.T) {
	ctx := context.Background()
	groupID := int64(1010801)
	deepseekOwner := compositeMultiPlatformTestAccount(381001, PlatformDeepseek, 3, groupID, map[string]any{"deepseek-flash": "deepseek-flash"})
	openCodeOwner := compositeMultiPlatformTestAccount(381002, PlatformOpenCodeGo, 1, groupID, map[string]any{"deepseek-flash": "deepseek-v4.1-flash"})
	deepseekNonOwner := compositeMultiPlatformTestAccount(381003, PlatformDeepseek, 0, groupID, map[string]any{"deepseek-v4-pro": "deepseek-v4-pro"})
	kimiOwner := compositeMultiPlatformTestAccount(381004, PlatformKimi, 0, groupID, map[string]any{"deepseek-flash": "kimi-k3"})
	repo := schedulerTestOpenAIAccountRepo{accounts: []Account{deepseekOwner, openCodeOwner, deepseekNonOwner, kimiOwner}}
	ctx = WithCompositeRouteDecision(ctx, CompositeRouteDecision{
		Matched: true, Source: CompositeRouteSourceAccount, GroupID: groupID,
		PublicModel: "deepseek-flash", TargetPlatform: PlatformDeepseek, UpstreamModel: "deepseek-flash",
		CandidatePlatforms: []string{PlatformDeepseek, PlatformOpenCodeGo},
	})

	for _, advanced := range []string{"true", "false"} {
		for _, tt := range []struct {
			name            string
			sessionHash     string
			sessionBindings map[string]int64
			excluded        map[int64]struct{}
			want            int64
			anyOwner        bool
		}{
			{name: "highest priority owner across platforms", want: openCodeOwner.ID},
			{name: "failover to other platform owner", excluded: map[int64]struct{}{openCodeOwner.ID: {}}, want: deepseekOwner.ID},
			{name: "sticky hit on other candidate platform", sessionHash: "sticky", sessionBindings: map[string]int64{"openai:sticky": deepseekOwner.ID}, want: deepseekOwner.ID},
			{name: "sticky hit on non owner is rejected", sessionHash: "non-owner", sessionBindings: map[string]int64{"openai:non-owner": deepseekNonOwner.ID}, anyOwner: true},
		} {
			t.Run("advanced="+advanced+"/"+tt.name, func(t *testing.T) {
				resetOpenAIAdvancedSchedulerSettingCacheForTest()
				cfg := &config.Config{}
				cfg.Gateway.Scheduling.LoadBatchEnabled = false
				svc := &OpenAIGatewayService{
					accountRepo:        repo,
					cache:              &schedulerTestGatewayCache{sessionBindings: tt.sessionBindings},
					cfg:                cfg,
					rateLimitService:   newOpenAIAdvancedSchedulerRateLimitService(advanced),
					concurrencyService: NewConcurrencyService(schedulerTestConcurrencyCache{}),
				}

				selectOnce := func() int64 {
					selection, _, err := svc.SelectAccountWithSchedulerForCapability(
						ctx, &groupID, "", tt.sessionHash, "deepseek-flash", tt.excluded,
						OpenAIUpstreamTransportAny, OpenAIEndpointCapabilityChatCompletions, false, false, true, PlatformDeepseek,
					)
					require.NoError(t, err)
					require.NotNil(t, selection)
					require.NotNil(t, selection.Account)
					if selection.ReleaseFunc != nil {
						selection.ReleaseFunc()
					}
					return selection.Account.ID
				}
				if tt.anyOwner {
					require.Contains(t, []int64{deepseekOwner.ID, openCodeOwner.ID}, selectOnce())
					return
				}
				if advanced == "false" || tt.sessionHash != "" || tt.excluded != nil {
					require.Equal(t, tt.want, selectOnce())
					return
				}
				// 高级调度器在优先级/负载加权的候选中随机选号：只要求始终落在认领账号上，
				// 且跨平台的最高优先级账号能被选中。
				seen := map[int64]int{}
				for i := 0; i < 40; i++ {
					seen[selectOnce()]++
				}
				for id := range seen {
					require.Contains(t, []int64{deepseekOwner.ID, openCodeOwner.ID}, id)
				}
				require.Positive(t, seen[tt.want])
			})
		}
	}
}

// 没有候选集合时保持单平台调度：opencode 账号不会被 deepseek 请求选中。
func TestOpenAIGatewayService_SelectAccountWithScheduler_WithoutCandidatesStaysSinglePlatform(t *testing.T) {
	resetOpenAIAdvancedSchedulerSettingCacheForTest()
	ctx := context.Background()
	groupID := int64(1010802)
	deepseekAccount := compositeMultiPlatformTestAccount(382001, PlatformDeepseek, 3, groupID, nil)
	openCodeAccount := compositeMultiPlatformTestAccount(382002, PlatformOpenCodeGo, 1, groupID, nil)
	cfg := &config.Config{}
	cfg.Gateway.Scheduling.LoadBatchEnabled = false
	svc := &OpenAIGatewayService{
		accountRepo:        schedulerTestOpenAIAccountRepo{accounts: []Account{deepseekAccount, openCodeAccount}},
		cache:              &schedulerTestGatewayCache{},
		cfg:                cfg,
		rateLimitService:   newOpenAIAdvancedSchedulerRateLimitService("true"),
		concurrencyService: NewConcurrencyService(schedulerTestConcurrencyCache{}),
	}

	selection, _, err := svc.SelectAccountWithSchedulerForCapability(
		ctx, &groupID, "", "", "deepseek-flash", nil,
		OpenAIUpstreamTransportAny, OpenAIEndpointCapabilityChatCompletions, false, false, true, PlatformDeepseek,
	)
	require.NoError(t, err)
	require.NotNil(t, selection)
	require.Equal(t, deepseekAccount.ID, selection.Account.ID)
	if selection.ReleaseFunc != nil {
		selection.ReleaseFunc()
	}
}
