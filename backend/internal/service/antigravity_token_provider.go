package service

import (
	"context"
	"errors"
	"log"
	"strconv"
	"strings"
	"time"
)

const (
	// antigravityTokenAsyncRefreshWindow 异步刷新窗口：5 分钟
	// 当 token 剩余有效期小于此值时触发异步刷新，但仍使用当前 token
	antigravityTokenAsyncRefreshWindow = 5 * time.Minute
	// antigravityTokenSyncRefreshWindow 同步刷新窗口：1 分钟
	// 当 token 剩余有效期小于此值时必须等待刷新完成
	antigravityTokenSyncRefreshWindow = 1 * time.Minute
	// antigravityTokenCacheSkew 缓存提前失效偏移
	antigravityTokenCacheSkew = 5 * time.Minute
	// antigravityRefreshTimeout 刷新超时时间
	antigravityRefreshTimeout = 30 * time.Second
)

// AntigravityTokenCache Token 缓存接口（复用 GeminiTokenCache 接口定义）
type AntigravityTokenCache = GeminiTokenCache

// AntigravityTokenProvider 管理 Antigravity 账户的 access_token（按需刷新）
type AntigravityTokenProvider struct {
	accountRepo        AccountRepository
	tokenCache         AntigravityTokenCache
	refreshCoordinator *TokenRefreshCoordinator
}

func NewAntigravityTokenProvider(
	accountRepo AccountRepository,
	tokenCache AntigravityTokenCache,
	refreshCoordinator *TokenRefreshCoordinator,
) *AntigravityTokenProvider {
	return &AntigravityTokenProvider{
		accountRepo:        accountRepo,
		tokenCache:         tokenCache,
		refreshCoordinator: refreshCoordinator,
	}
}

// GetAccessToken 获取有效的 access_token（按需刷新）
// 刷新策略：
// - token 剩余有效期 > 5 分钟：直接返回，不刷新
// - token 剩余有效期 1~5 分钟：触发异步刷新，返回当前 token
// - token 剩余有效期 < 1 分钟或已过期：等待刷新完成
func (p *AntigravityTokenProvider) GetAccessToken(ctx context.Context, account *Account) (string, error) {
	if account == nil {
		return "", errors.New("account is nil")
	}
	if account.Platform != PlatformAntigravity || account.Type != AccountTypeOAuth {
		return "", errors.New("not an antigravity oauth account")
	}

	cacheKey := antigravityTokenCacheKey(account)

	// 1. 先尝试缓存
	if p.tokenCache != nil {
		if token, err := p.tokenCache.GetAccessToken(ctx, cacheKey); err == nil && strings.TrimSpace(token) != "" {
			return token, nil
		}
	}

	// 2. 检查 token 有效期
	// 注意：expiresAt == nil 时 timeUntilExpiry = 0，会进入 default 分支执行同步刷新
	expiresAt := account.GetCredentialAsTime("expires_at")
	var timeUntilExpiry time.Duration
	if expiresAt != nil {
		timeUntilExpiry = time.Until(*expiresAt)
	}

	// 3. 根据剩余有效期决定刷新策略
	switch {
	case expiresAt != nil && timeUntilExpiry > antigravityTokenAsyncRefreshWindow:
		// 剩余 > 5 分钟：直接返回，不刷新
		accessToken := account.GetCredential("access_token")
		if strings.TrimSpace(accessToken) == "" {
			return "", errors.New("access_token not found in credentials")
		}
		// 存入缓存
		if p.tokenCache != nil {
			ttl := timeUntilExpiry - antigravityTokenCacheSkew
			if ttl > 0 {
				_ = p.tokenCache.SetAccessToken(ctx, cacheKey, accessToken, ttl)
			}
		}
		return accessToken, nil

	case expiresAt != nil && timeUntilExpiry > antigravityTokenSyncRefreshWindow:
		// 剩余 1~5 分钟：触发异步刷新，返回当前 token
		if p.refreshCoordinator != nil {
			resultCh := p.refreshCoordinator.TriggerRefresh(ctx, account.ID)
			// 非阻塞消费（channel 有 buffer=1，此时结果未就绪直接跳过）
			select {
			case <-resultCh:
			default:
			}
		}

		accessToken := account.GetCredential("access_token")
		if strings.TrimSpace(accessToken) != "" {
			// 存入缓存（TTL 减去 skew）
			if p.tokenCache != nil && timeUntilExpiry > antigravityTokenCacheSkew {
				_ = p.tokenCache.SetAccessToken(ctx, cacheKey, accessToken, timeUntilExpiry-antigravityTokenCacheSkew)
			}
			return accessToken, nil
		}
		// 如果当前 token 为空，降级到同步刷新
		fallthrough

	default:
		// 剩余 < 1 分钟或已过期：必须等待刷新完成
		if p.refreshCoordinator == nil {
			return "", errors.New("token expired and refresh coordinator not configured")
		}

		log.Printf("[AntigravityTokenProvider] Account %d: token expired/expiring, waiting for refresh (remaining=%v)",
			account.ID, timeUntilExpiry)

		resultCh := p.refreshCoordinator.TriggerRefresh(ctx, account.ID)
		select {
		case result := <-resultCh:
			// coordinator 超时会返回 ctx.Err()，无需额外超时
			if result.Err != nil {
				log.Printf("[AntigravityTokenProvider] Account %d: refresh failed: %v", account.ID, result.Err)
				return "", result.Err
			}
			log.Printf("[AntigravityTokenProvider] Account %d: refresh succeeded", account.ID)
			// 刷新成功，存入缓存
			if p.tokenCache != nil && strings.TrimSpace(result.Token) != "" {
				// 刷新后的 token 有效期约 55 分钟，缓存 50 分钟
				_ = p.tokenCache.SetAccessToken(ctx, cacheKey, result.Token, 50*time.Minute)
			}
			return result.Token, nil
		case <-ctx.Done():
			log.Printf("[AntigravityTokenProvider] Account %d: context cancelled while waiting for refresh", account.ID)
			return "", ctx.Err()
		}
	}
}

func antigravityTokenCacheKey(account *Account) string {
	projectID := strings.TrimSpace(account.GetCredential("project_id"))
	if projectID != "" {
		return "ag:" + projectID
	}
	return "ag:account:" + strconv.FormatInt(account.ID, 10)
}
