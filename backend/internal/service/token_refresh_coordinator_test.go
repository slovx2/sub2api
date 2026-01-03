//go:build unit

package service

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/pagination"
	"github.com/stretchr/testify/require"
)

// mockAccountRepo 模拟 AccountRepository（只实现测试需要的方法）
type mockAccountRepo struct {
	account *Account
	getErr  error
}

func (m *mockAccountRepo) Create(ctx context.Context, account *Account) error { return nil }
func (m *mockAccountRepo) GetByID(ctx context.Context, id int64) (*Account, error) {
	return m.account, m.getErr
}
func (m *mockAccountRepo) GetByIDs(ctx context.Context, ids []int64) ([]*Account, error) {
	return nil, nil
}
func (m *mockAccountRepo) ExistsByID(ctx context.Context, id int64) (bool, error) { return true, nil }
func (m *mockAccountRepo) GetByCRSAccountID(ctx context.Context, id string) (*Account, error) {
	return nil, nil
}
func (m *mockAccountRepo) Update(ctx context.Context, account *Account) error { return nil }
func (m *mockAccountRepo) Delete(ctx context.Context, id int64) error         { return nil }
func (m *mockAccountRepo) List(ctx context.Context, params pagination.PaginationParams) ([]Account, *pagination.PaginationResult, error) {
	return nil, nil, nil
}
func (m *mockAccountRepo) ListWithFilters(ctx context.Context, params pagination.PaginationParams, platform, accountType, status, search string) ([]Account, *pagination.PaginationResult, error) {
	return nil, nil, nil
}
func (m *mockAccountRepo) ListByGroup(ctx context.Context, groupID int64) ([]Account, error) {
	return nil, nil
}
func (m *mockAccountRepo) ListActive(ctx context.Context) ([]Account, error) { return nil, nil }
func (m *mockAccountRepo) ListByPlatform(ctx context.Context, platform string) ([]Account, error) {
	return nil, nil
}
func (m *mockAccountRepo) UpdateLastUsed(ctx context.Context, id int64) error { return nil }
func (m *mockAccountRepo) BatchUpdateLastUsed(ctx context.Context, updates map[int64]time.Time) error {
	return nil
}
func (m *mockAccountRepo) SetError(ctx context.Context, id int64, msg string) error { return nil }
func (m *mockAccountRepo) SetSchedulable(ctx context.Context, id int64, schedulable bool) error {
	return nil
}
func (m *mockAccountRepo) BindGroups(ctx context.Context, accountID int64, groupIDs []int64) error {
	return nil
}
func (m *mockAccountRepo) ListSchedulable(ctx context.Context) ([]Account, error) { return nil, nil }
func (m *mockAccountRepo) ListSchedulableByGroupID(ctx context.Context, groupID int64) ([]Account, error) {
	return nil, nil
}
func (m *mockAccountRepo) ListSchedulableByPlatform(ctx context.Context, platform string) ([]Account, error) {
	return nil, nil
}
func (m *mockAccountRepo) ListSchedulableByGroupIDAndPlatform(ctx context.Context, groupID int64, platform string) ([]Account, error) {
	return nil, nil
}
func (m *mockAccountRepo) ListSchedulableByPlatforms(ctx context.Context, platforms []string) ([]Account, error) {
	return nil, nil
}
func (m *mockAccountRepo) ListSchedulableByGroupIDAndPlatforms(ctx context.Context, groupID int64, platforms []string) ([]Account, error) {
	return nil, nil
}
func (m *mockAccountRepo) SetRateLimited(ctx context.Context, id int64, resetAt time.Time) error {
	return nil
}
func (m *mockAccountRepo) SetOverloaded(ctx context.Context, id int64, until time.Time) error {
	return nil
}
func (m *mockAccountRepo) ClearRateLimit(ctx context.Context, id int64) error { return nil }
func (m *mockAccountRepo) UpdateSessionWindow(ctx context.Context, id int64, start, end *time.Time, status string) error {
	return nil
}
func (m *mockAccountRepo) UpdateExtra(ctx context.Context, id int64, updates map[string]any) error {
	return nil
}
func (m *mockAccountRepo) BulkUpdate(ctx context.Context, ids []int64, updates AccountBulkUpdate) (int64, error) {
	return 0, nil
}

// mockOAuthService 模拟 AntigravityOAuthService，刷新耗时 3 秒
type mockOAuthService struct {
	refreshDelay time.Duration
	refreshCount atomic.Int32
	tokenInfo    *AntigravityTokenInfo
	refreshErr   error
}

func (m *mockOAuthService) RefreshAccountToken(ctx context.Context, account *Account) (*AntigravityTokenInfo, error) {
	m.refreshCount.Add(1)
	select {
	case <-time.After(m.refreshDelay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if m.refreshErr != nil {
		return nil, m.refreshErr
	}
	return m.tokenInfo, nil
}

func (m *mockOAuthService) BuildAccountCredentials(tokenInfo *AntigravityTokenInfo) map[string]any {
	return map[string]any{
		"access_token": tokenInfo.AccessToken,
		"expires_at":   time.Now().Add(55 * time.Minute).Format(time.RFC3339),
	}
}

// mockTokenCache 模拟缓存
type mockTokenCache struct {
	tokens map[string]string
	mu     sync.Mutex
}

func newMockTokenCache() *mockTokenCache {
	return &mockTokenCache{tokens: make(map[string]string)}
}

func (m *mockTokenCache) GetAccessToken(ctx context.Context, key string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.tokens[key], nil
}

func (m *mockTokenCache) SetAccessToken(ctx context.Context, key, token string, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens[key] = token
	return nil
}

func (m *mockTokenCache) AcquireRefreshLock(ctx context.Context, cacheKey string, ttl time.Duration) (bool, error) {
	return true, nil
}

func (m *mockTokenCache) ReleaseRefreshLock(ctx context.Context, cacheKey string) error {
	return nil
}

// 创建测试用的 coordinator，使用注入的 mock OAuth service
func newTestCoordinator(
	accountRepo AccountRepository,
	oauthSvc *mockOAuthService,
	tokenCache GeminiTokenCache,
) *TokenRefreshCoordinator {
	coord := &TokenRefreshCoordinator{
		inProgress:  make(map[int64][]chan RefreshResult),
		accountRepo: accountRepo,
		tokenCache:  tokenCache,
	}
	// 注入 mock refresh 函数
	coord.refreshFunc = oauthSvc.RefreshAccountToken
	coord.buildCredentialsFunc = oauthSvc.BuildAccountCredentials
	return coord
}

func TestTokenRefreshCoordinator_MultipleGoroutines_SingleRefresh(t *testing.T) {
	// 准备：刷新耗时 3 秒
	oauthSvc := &mockOAuthService{
		refreshDelay: 3 * time.Second,
		tokenInfo: &AntigravityTokenInfo{
			AccessToken: "new-access-token",
			ExpiresIn:   3300,
		},
	}

	account := &Account{
		ID:       1,
		Platform: PlatformAntigravity,
		Type:     AccountTypeOAuth,
		Credentials: map[string]any{
			"access_token":  "old-token",
			"refresh_token": "refresh-token",
			"expires_at":    time.Now().Add(-1 * time.Minute).Format(time.RFC3339), // 已过期
		},
	}

	accountRepo := &mockAccountRepo{account: account}
	cache := newMockTokenCache()
	coord := newTestCoordinator(accountRepo, oauthSvc, cache)

	// 10 个协程同时触发刷新
	const goroutineCount = 10
	var wg sync.WaitGroup
	results := make([]RefreshResult, goroutineCount)

	ctx := context.Background()
	startTime := time.Now()

	for i := 0; i < goroutineCount; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			resultCh := coord.TriggerRefresh(ctx, account.ID)
			results[idx] = <-resultCh
		}(i)
	}

	wg.Wait()
	elapsed := time.Since(startTime)

	// 验证：只触发一次刷新
	require.Equal(t, int32(1), oauthSvc.refreshCount.Load(), "应该只触发一次刷新")

	// 验证：耗时约 3 秒（允许 0.5 秒误差）
	require.GreaterOrEqual(t, elapsed, 3*time.Second, "应该等待刷新完成")
	require.Less(t, elapsed, 4*time.Second, "不应超时太久")

	// 验证：所有协程都收到相同的结果
	for i, result := range results {
		require.NoError(t, result.Err, "协程 %d 不应有错误", i)
		require.Equal(t, "new-access-token", result.Token, "协程 %d 应收到新 token", i)
	}
}

func TestTokenRefreshCoordinator_RefreshError_AllWaitersReceiveError(t *testing.T) {
	// 刷新失败场景
	oauthSvc := &mockOAuthService{
		refreshDelay: 100 * time.Millisecond,
		refreshErr:   errors.New("invalid_grant: token revoked"),
	}

	account := &Account{
		ID:       2,
		Platform: PlatformAntigravity,
		Type:     AccountTypeOAuth,
		Credentials: map[string]any{
			"refresh_token": "invalid-refresh-token",
			"expires_at":    time.Now().Add(-1 * time.Minute).Format(time.RFC3339),
		},
	}

	accountRepo := &mockAccountRepo{account: account}
	coord := newTestCoordinator(accountRepo, oauthSvc, nil)

	const goroutineCount = 5
	var wg sync.WaitGroup
	results := make([]RefreshResult, goroutineCount)

	ctx := context.Background()

	for i := 0; i < goroutineCount; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			resultCh := coord.TriggerRefresh(ctx, account.ID)
			results[idx] = <-resultCh
		}(i)
	}

	wg.Wait()

	// 验证：只触发一次刷新
	require.Equal(t, int32(1), oauthSvc.refreshCount.Load())

	// 验证：所有协程都收到错误
	for i, result := range results {
		require.Error(t, result.Err, "协程 %d 应收到错误", i)
		require.Contains(t, result.Err.Error(), "invalid_grant")
	}
}

// === AntigravityTokenProvider 三种时间区间测试 ===

func TestAntigravityTokenProvider_ExpiryTimeWindows(t *testing.T) {
	ctx := context.Background()

	t.Run("剩余>5分钟：直接返回，不刷新", func(t *testing.T) {
		oauthSvc := &mockOAuthService{
			refreshDelay: 3 * time.Second,
			tokenInfo:    &AntigravityTokenInfo{AccessToken: "should-not-be-used"},
		}

		account := &Account{
			ID:       10,
			Platform: PlatformAntigravity,
			Type:     AccountTypeOAuth,
			Credentials: map[string]any{
				"access_token":  "valid-token",
				"refresh_token": "refresh-token",
				"expires_at":    time.Now().Add(10 * time.Minute).Format(time.RFC3339), // 剩余 10 分钟
			},
		}

		accountRepo := &mockAccountRepo{account: account}
		cache := newMockTokenCache()
		coord := newTestCoordinator(accountRepo, oauthSvc, cache)
		provider := NewAntigravityTokenProvider(accountRepo, cache, coord)

		token, err := provider.GetAccessToken(ctx, account)
		require.NoError(t, err)
		require.Equal(t, "valid-token", token, "应返回当前有效的 token")
		require.NotEqual(t, "should-not-be-used", token, "不应返回刷新后的 token")
		// 不应触发刷新
		require.Equal(t, int32(0), oauthSvc.refreshCount.Load(), "不应触发刷新")
	})

	t.Run("剩余1-5分钟：触发异步刷新，返回当前token", func(t *testing.T) {
		oauthSvc := &mockOAuthService{
			refreshDelay: 3 * time.Second,
			tokenInfo:    &AntigravityTokenInfo{AccessToken: "refreshed-new-token", ExpiresIn: 3300},
		}

		account := &Account{
			ID:       11,
			Platform: PlatformAntigravity,
			Type:     AccountTypeOAuth,
			Credentials: map[string]any{
				"access_token":  "almost-expired-token",
				"refresh_token": "refresh-token",
				"expires_at":    time.Now().Add(3 * time.Minute).Format(time.RFC3339), // 剩余 3 分钟
			},
		}

		accountRepo := &mockAccountRepo{account: account}
		cache := newMockTokenCache()
		coord := newTestCoordinator(accountRepo, oauthSvc, cache)
		provider := NewAntigravityTokenProvider(accountRepo, cache, coord)

		startTime := time.Now()
		token, err := provider.GetAccessToken(ctx, account)
		elapsed := time.Since(startTime)

		require.NoError(t, err)
		require.Equal(t, "almost-expired-token", token, "应返回当前 token（异步刷新不阻塞）")
		require.NotEqual(t, "refreshed-new-token", token, "不应返回刷新后的 token（异步刷新未完成）")
		require.Less(t, elapsed, 100*time.Millisecond, "应立即返回，不等待刷新")

		// 等待异步刷新完成
		time.Sleep(3500 * time.Millisecond)
		require.Equal(t, int32(1), oauthSvc.refreshCount.Load(), "应触发一次异步刷新")
	})

	t.Run("剩余<1分钟：同步等待刷新完成", func(t *testing.T) {
		oauthSvc := &mockOAuthService{
			refreshDelay: 3 * time.Second,
			tokenInfo:    &AntigravityTokenInfo{AccessToken: "brand-new-token", ExpiresIn: 3300},
		}

		account := &Account{
			ID:       12,
			Platform: PlatformAntigravity,
			Type:     AccountTypeOAuth,
			Credentials: map[string]any{
				"access_token":  "about-to-expire-token",
				"refresh_token": "refresh-token",
				"expires_at":    time.Now().Add(30 * time.Second).Format(time.RFC3339), // 剩余 30 秒
			},
		}

		accountRepo := &mockAccountRepo{account: account}
		cache := newMockTokenCache()
		coord := newTestCoordinator(accountRepo, oauthSvc, cache)
		provider := NewAntigravityTokenProvider(accountRepo, cache, coord)

		startTime := time.Now()
		token, err := provider.GetAccessToken(ctx, account)
		elapsed := time.Since(startTime)

		require.NoError(t, err)
		require.Equal(t, "brand-new-token", token, "应返回刷新后的新 token")
		require.NotEqual(t, "about-to-expire-token", token, "不应返回即将过期的旧 token")
		require.GreaterOrEqual(t, elapsed, 3*time.Second, "应等待刷新完成")
		require.Equal(t, int32(1), oauthSvc.refreshCount.Load(), "应触发一次刷新")
	})

	t.Run("已过期：同步等待刷新完成", func(t *testing.T) {
		oauthSvc := &mockOAuthService{
			refreshDelay: 3 * time.Second,
			tokenInfo:    &AntigravityTokenInfo{AccessToken: "fresh-new-token", ExpiresIn: 3300},
		}

		account := &Account{
			ID:       13,
			Platform: PlatformAntigravity,
			Type:     AccountTypeOAuth,
			Credentials: map[string]any{
				"access_token":  "already-expired-token",
				"refresh_token": "refresh-token",
				"expires_at":    time.Now().Add(-5 * time.Minute).Format(time.RFC3339), // 已过期 5 分钟
			},
		}

		accountRepo := &mockAccountRepo{account: account}
		cache := newMockTokenCache()
		coord := newTestCoordinator(accountRepo, oauthSvc, cache)
		provider := NewAntigravityTokenProvider(accountRepo, cache, coord)

		startTime := time.Now()
		token, err := provider.GetAccessToken(ctx, account)
		elapsed := time.Since(startTime)

		require.NoError(t, err)
		require.Equal(t, "fresh-new-token", token, "应返回刷新后的新 token")
		require.NotEqual(t, "already-expired-token", token, "不应返回已过期的旧 token")
		require.GreaterOrEqual(t, elapsed, 3*time.Second, "应等待刷新完成")
		require.Equal(t, int32(1), oauthSvc.refreshCount.Load(), "应触发一次刷新")
	})
}

// 测试多个协程同时访问 AntigravityTokenProvider，期望只触发一次刷新
func TestAntigravityTokenProvider_MultipleGoroutines_SingleRefresh(t *testing.T) {
	oauthSvc := &mockOAuthService{
		refreshDelay: 3 * time.Second,
		tokenInfo:    &AntigravityTokenInfo{AccessToken: "concurrent-new-token", ExpiresIn: 3300},
	}

	account := &Account{
		ID:       20,
		Platform: PlatformAntigravity,
		Type:     AccountTypeOAuth,
		Credentials: map[string]any{
			"access_token":  "concurrent-old-token",
			"refresh_token": "refresh-token",
			"expires_at":    time.Now().Add(-1 * time.Minute).Format(time.RFC3339), // 已过期
		},
	}

	accountRepo := &mockAccountRepo{account: account}
	cache := newMockTokenCache()
	coord := newTestCoordinator(accountRepo, oauthSvc, cache)
	provider := NewAntigravityTokenProvider(accountRepo, cache, coord)

	const goroutineCount = 10
	var wg sync.WaitGroup
	tokens := make([]string, goroutineCount)
	errs := make([]error, goroutineCount)

	ctx := context.Background()
	startTime := time.Now()

	for i := 0; i < goroutineCount; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			tokens[idx], errs[idx] = provider.GetAccessToken(ctx, account)
		}(i)
	}

	wg.Wait()
	elapsed := time.Since(startTime)

	// 验证：只触发一次刷新
	require.Equal(t, int32(1), oauthSvc.refreshCount.Load(), "应该只触发一次刷新")

	// 验证：耗时约 3 秒
	require.GreaterOrEqual(t, elapsed, 3*time.Second, "应等待刷新完成")
	require.Less(t, elapsed, 4*time.Second, "不应超时太久")

	// 验证：所有协程都收到相同的新 token
	for i := range goroutineCount {
		require.NoError(t, errs[i], "协程 %d 不应有错误", i)
		require.Equal(t, "concurrent-new-token", tokens[i], "协程 %d 应收到刷新后的新 token", i)
		require.NotEqual(t, "concurrent-old-token", tokens[i], "协程 %d 不应收到旧 token", i)
	}
}
