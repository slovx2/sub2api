package service

import (
	"context"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/stretchr/testify/require"
)

// imagePriorityAccountRepo 在分组感知的调度桩上补充 GetByIDs（优先账号按 ID 读取）。
type imagePriorityAccountRepo struct {
	schedulerGroupAwareOpenAIAccountRepo
}

func (r imagePriorityAccountRepo) GetByIDs(ctx context.Context, ids []int64) ([]*Account, error) {
	result := make([]*Account, 0, len(ids))
	for _, id := range ids {
		for i := range r.accounts {
			if r.accounts[i].ID == id {
				account := r.accounts[i]
				result = append(result, &account)
			}
		}
	}
	return result, nil
}

const imagePriorityTestGroupID int64 = 9100

func newImagePriorityTestService(t *testing.T, accounts []Account, priorityIDs []int64, cache schedulerTestConcurrencyCache) *OpenAIGatewayService {
	t.Helper()
	resetOpenAIAdvancedSchedulerSettingCacheForTest()
	settingService := NewSettingService(&gatewayTTLSettingRepo{}, &config.Config{})
	_, err := settingService.SetOpenAIImagePriorityAccountIDs(context.Background(), priorityIDs)
	require.NoError(t, err)
	cfg := &config.Config{}
	cfg.Gateway.Scheduling.LoadBatchEnabled = false
	return &OpenAIGatewayService{
		accountRepo:        imagePriorityAccountRepo{schedulerGroupAwareOpenAIAccountRepo{schedulerTestOpenAIAccountRepo{accounts: accounts}}},
		cache:              &schedulerTestGatewayCache{},
		cfg:                cfg,
		settingService:     settingService,
		concurrencyService: NewConcurrencyService(cache),
	}
}

// groupImageAccount 是分组内常规可调度的 OpenAI 账号，作为回退目标。
func groupImageAccount() Account {
	return Account{
		ID:          9201,
		Platform:    PlatformOpenAI,
		Type:        AccountTypeOAuth,
		Status:      StatusActive,
		Schedulable: true,
		Concurrency: 5,
		GroupIDs:    []int64{imagePriorityTestGroupID},
	}
}

// priorityImageAccount 是不在分组内、且关闭了调度开关的图片优先账号。
func priorityImageAccount(id int64) Account {
	return Account{
		ID:          id,
		Platform:    PlatformOpenAI,
		Type:        AccountTypeOAuth,
		Status:      StatusActive,
		Schedulable: false,
		Concurrency: 5,
	}
}

func selectImageAccountForTest(t *testing.T, svc *OpenAIGatewayService, excluded map[int64]struct{}) (*AccountSelectionResult, OpenAIAccountScheduleDecision) {
	t.Helper()
	groupID := imagePriorityTestGroupID
	// 与 handler 一致：图片端点上下文携带生图意图，使生图冷却键参与模型级限流判断。
	ctx := WithOpenAIImagesEndpoint(WithOpenAIImageGenerationIntent(context.Background()))
	selection, decision, err := svc.SelectAccountWithSchedulerForImages(
		ctx, &groupID, "", "gpt-image-2", excluded, OpenAIImagesCapabilityBasic,
	)
	require.NoError(t, err)
	require.NotNil(t, selection)
	require.NotNil(t, selection.Account)
	return selection, decision
}

func TestSelectImages_PriorityAccountIgnoresSchedulableSwitchAndGroup(t *testing.T) {
	svc := newImagePriorityTestService(t,
		[]Account{groupImageAccount(), priorityImageAccount(9301)},
		[]int64{9301},
		schedulerTestConcurrencyCache{},
	)
	selection, decision := selectImageAccountForTest(t, svc, nil)
	require.Equal(t, int64(9301), selection.Account.ID)
	require.True(t, selection.Acquired)
	require.Equal(t, openAIAccountScheduleLayerImagePriority, decision.Layer)
}

func TestSelectImages_PriorityAccountWithBadStatusFallsBack(t *testing.T) {
	future := time.Now().Add(time.Hour)
	cases := map[string]func(*Account){
		"status_error":       func(a *Account) { a.Status = StatusError },
		"status_disabled":    func(a *Account) { a.Status = StatusDisabled },
		"rate_limited":       func(a *Account) { a.RateLimitResetAt = &future },
		"overloaded":         func(a *Account) { a.OverloadUntil = &future },
		"temp_unschedulable": func(a *Account) { a.TempUnschedulableUntil = &future },
		"not_openai":         func(a *Account) { a.Platform = PlatformAnthropic },
		"model_not_allowed": func(a *Account) {
			a.Credentials = map[string]any{"model_mapping": map[string]any{"gpt-5.4": "gpt-5.4"}}
		},
		"image_tool_cooldown": func(a *Account) {
			a.Extra = map[string]any{"model_rate_limits": map[string]any{
				openAIImageGenerationRateLimitKey: map[string]any{
					"rate_limited_at":     time.Now().Format(time.RFC3339),
					"rate_limit_reset_at": future.Format(time.RFC3339),
				},
			}}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			priority := priorityImageAccount(9302)
			mutate(&priority)
			svc := newImagePriorityTestService(t,
				[]Account{groupImageAccount(), priority},
				[]int64{9302},
				schedulerTestConcurrencyCache{},
			)
			selection, decision := selectImageAccountForTest(t, svc, nil)
			require.Equal(t, int64(9201), selection.Account.ID)
			require.NotEqual(t, openAIAccountScheduleLayerImagePriority, decision.Layer)
		})
	}
}

func TestSelectImages_ExcludedPriorityAccountFallsBack(t *testing.T) {
	svc := newImagePriorityTestService(t,
		[]Account{groupImageAccount(), priorityImageAccount(9303)},
		[]int64{9303},
		schedulerTestConcurrencyCache{},
	)
	selection, _ := selectImageAccountForTest(t, svc, map[int64]struct{}{9303: {}})
	require.Equal(t, int64(9201), selection.Account.ID)
}

func TestSelectImages_PriorityAccountConcurrencyFullFallsBack(t *testing.T) {
	svc := newImagePriorityTestService(t,
		[]Account{groupImageAccount(), priorityImageAccount(9304)},
		[]int64{9304},
		schedulerTestConcurrencyCache{acquireResults: map[int64]bool{9304: false}},
	)
	selection, _ := selectImageAccountForTest(t, svc, nil)
	require.Equal(t, int64(9201), selection.Account.ID)
}

func TestSelectImages_PriorityAccountsOrderedByAccountPriority(t *testing.T) {
	low := priorityImageAccount(9305)
	low.Priority = 5
	high := priorityImageAccount(9306)
	high.Priority = 1
	svc := newImagePriorityTestService(t,
		[]Account{groupImageAccount(), low, high},
		[]int64{9305, 9306},
		schedulerTestConcurrencyCache{},
	)
	selection, _ := selectImageAccountForTest(t, svc, nil)
	require.Equal(t, int64(9306), selection.Account.ID)

	// 首选失败被排除后轮到下一个优先账号，而不是直接回退分组。
	selection, decision := selectImageAccountForTest(t, svc, map[int64]struct{}{9306: {}})
	require.Equal(t, int64(9305), selection.Account.ID)
	require.Equal(t, openAIAccountScheduleLayerImagePriority, decision.Layer)
}

func TestSelectImages_NoPriorityConfiguredUsesNormalScheduling(t *testing.T) {
	svc := newImagePriorityTestService(t,
		[]Account{groupImageAccount(), priorityImageAccount(9307)},
		nil,
		schedulerTestConcurrencyCache{},
	)
	selection, _ := selectImageAccountForTest(t, svc, nil)
	require.Equal(t, int64(9201), selection.Account.ID)
}

func TestAccountIsSchedulableIgnoringManualSwitch(t *testing.T) {
	account := priorityImageAccount(1)
	require.False(t, account.IsSchedulable())
	require.True(t, account.IsSchedulableIgnoringManualSwitch())
	account.Status = StatusError
	require.False(t, account.IsSchedulableIgnoringManualSwitch())
}

func TestNormalizeOpenAIImagePriorityAccountIDs(t *testing.T) {
	require.Equal(t, []int64{3, 1, 2}, normalizeOpenAIImagePriorityAccountIDs([]int64{3, 0, 1, 3, -2, 2, 1}))
	require.Equal(t, []int64{}, parseOpenAIImagePriorityAccountIDs("not-json"))
	require.Equal(t, []int64{5, 6}, parseOpenAIImagePriorityAccountIDs("[5,6,5]"))
}

func TestSetOpenAIImagePriorityAccountIDs_RejectsTooMany(t *testing.T) {
	settingService := NewSettingService(&gatewayTTLSettingRepo{}, &config.Config{})
	ids := make([]int64, 0, MaxOpenAIImagePriorityAccounts+1)
	for i := int64(1); i <= MaxOpenAIImagePriorityAccounts+1; i++ {
		ids = append(ids, i)
	}
	_, err := settingService.SetOpenAIImagePriorityAccountIDs(context.Background(), ids)
	require.Error(t, err)
}

func TestAdminUpdateOpenAIImagePriorityAccounts_Validation(t *testing.T) {
	anthropic := Account{ID: 9402, Platform: PlatformAnthropic, Status: StatusActive}
	repo := imagePriorityAccountRepo{schedulerGroupAwareOpenAIAccountRepo{schedulerTestOpenAIAccountRepo{
		accounts: []Account{priorityImageAccount(9401), anthropic},
	}}}
	settingService := NewSettingService(&gatewayTTLSettingRepo{}, &config.Config{})
	admin := &adminServiceImpl{accountRepo: repo, settingService: settingService}
	ctx := context.Background()

	_, err := admin.UpdateOpenAIImagePriorityAccounts(ctx, []int64{9401, 9999})
	require.ErrorContains(t, err, "not found")
	_, err = admin.UpdateOpenAIImagePriorityAccounts(ctx, []int64{9401, 9402})
	require.ErrorContains(t, err, "not an OpenAI account")

	saved, err := admin.UpdateOpenAIImagePriorityAccounts(ctx, []int64{9401, 9401})
	require.NoError(t, err)
	require.Equal(t, []int64{9401}, saved.AccountIDs)

	got, err := admin.GetOpenAIImagePriorityAccounts(ctx)
	require.NoError(t, err)
	require.Equal(t, []int64{9401}, got.AccountIDs)
	require.Len(t, got.Accounts, 1)
	require.Equal(t, int64(9401), got.Accounts[0].ID)
}
