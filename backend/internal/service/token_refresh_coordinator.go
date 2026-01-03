package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

// RefreshResult 刷新结果
type RefreshResult struct {
	Token string
	Err   error
}

// RefreshErrorAction 刷新失败后的处理动作
type RefreshErrorAction int

const (
	ActionLogOnly        RefreshErrorAction = iota // 仅记录日志
	ActionSetRateLimited                           // 设置临时限流状态
	ActionSetError                                 // 设置错误状态（需用户介入）
)

// TokenRefreshCoordinator 管理账户级别的 token 刷新，确保同一账户同时只有一个刷新操作
type TokenRefreshCoordinator struct {
	mu         sync.Mutex
	inProgress map[int64][]chan RefreshResult // accountID -> 等待结果的 channels

	accountRepo             AccountRepository
	antigravityOAuthService *AntigravityOAuthService
	tokenCache              GeminiTokenCache

	// 可注入的函数（用于测试）
	refreshFunc          func(ctx context.Context, account *Account) (*AntigravityTokenInfo, error)
	buildCredentialsFunc func(tokenInfo *AntigravityTokenInfo) map[string]any
}

// NewTokenRefreshCoordinator 创建刷新协调器
func NewTokenRefreshCoordinator(
	accountRepo AccountRepository,
	antigravityOAuthService *AntigravityOAuthService,
	tokenCache GeminiTokenCache,
) *TokenRefreshCoordinator {
	return &TokenRefreshCoordinator{
		inProgress:              make(map[int64][]chan RefreshResult),
		accountRepo:             accountRepo,
		antigravityOAuthService: antigravityOAuthService,
		tokenCache:              tokenCache,
	}
}

// TriggerRefresh 触发账户 token 刷新
// 如果已有刷新在进行，则加入等待队列；否则启动新的刷新协程
// 返回用于接收结果的 channel
func (c *TokenRefreshCoordinator) TriggerRefresh(ctx context.Context, accountID int64) <-chan RefreshResult {
	c.mu.Lock()

	resultCh := make(chan RefreshResult, 1)

	// 检查是否已有刷新在进行
	if waiters, ok := c.inProgress[accountID]; ok {
		// 加入等待队列
		c.inProgress[accountID] = append(waiters, resultCh)
		waiterCount := len(c.inProgress[accountID])
		c.mu.Unlock()
		log.Printf("[TokenRefreshCoordinator] Account %d: joined existing refresh queue (waiters=%d)", accountID, waiterCount)
		return resultCh
	}

	// 启动新的刷新
	c.inProgress[accountID] = []chan RefreshResult{resultCh}
	c.mu.Unlock()

	log.Printf("[TokenRefreshCoordinator] Account %d: starting refresh", accountID)
	// 使用独立的 context，不受调用者 context 取消的影响
	// 刷新操作对所有等待者都有效，不应因单个请求取消而中断
	refreshCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	go func() {
		defer cancel()
		c.doRefresh(refreshCtx, accountID)
	}()

	return resultCh
}

// doRefresh 执行刷新操作
func (c *TokenRefreshCoordinator) doRefresh(ctx context.Context, accountID int64) {
	var result RefreshResult

	// 1. 获取最新账户信息
	account, err := c.accountRepo.GetByID(ctx, accountID)
	if err != nil {
		result = RefreshResult{Err: fmt.Errorf("failed to get account: %w", err)}
		c.notifyWaiters(accountID, result)
		return
	}
	if account == nil {
		result = RefreshResult{Err: errors.New("account not found")}
		c.notifyWaiters(accountID, result)
		return
	}

	// 2. 再次检查 token 是否仍需刷新（可能其他实例已刷新）
	expiresAt := account.GetCredentialAsTime("expires_at")
	if expiresAt != nil && time.Until(*expiresAt) > antigravityTokenAsyncRefreshWindow {
		// token 已被其他实例刷新，直接返回当前 token
		token := account.GetCredential("access_token")
		if strings.TrimSpace(token) != "" {
			log.Printf("[TokenRefreshCoordinator] Account %d: token already refreshed by another instance", accountID)
			result = RefreshResult{Token: token}
			c.notifyWaiters(accountID, result)
			return
		}
	}

	// 3. 执行刷新（带重试）
	tokenInfo, err := c.refreshWithRetry(ctx, account)
	if err != nil {
		c.handleRefreshError(ctx, account, err)
		result = RefreshResult{Err: err}
		c.notifyWaiters(accountID, result)
		return
	}

	// 4. 更新账户凭证
	newCredentials := c.getBuildCredentialsFunc()(tokenInfo)
	for k, v := range account.Credentials {
		if _, exists := newCredentials[k]; !exists {
			newCredentials[k] = v
		}
	}
	account.Credentials = newCredentials

	if updateErr := c.accountRepo.Update(ctx, account); updateErr != nil {
		log.Printf("[TokenRefreshCoordinator] Account %d: failed to update credentials: %v", accountID, updateErr)
		// 即使更新失败，token 仍然有效，继续返回
	}

	// 5. 更新缓存
	if c.tokenCache != nil {
		cacheKey := antigravityTokenCacheKey(account)
		ttl := 30 * time.Minute
		newExpiresAt := account.GetCredentialAsTime("expires_at")
		if newExpiresAt != nil {
			until := time.Until(*newExpiresAt)
			if until > antigravityTokenCacheSkew {
				ttl = until - antigravityTokenCacheSkew
			} else if until > 0 {
				ttl = until
			}
		}
		_ = c.tokenCache.SetAccessToken(ctx, cacheKey, tokenInfo.AccessToken, ttl)
	}

	log.Printf("[TokenRefreshCoordinator] Account %d: refresh completed", accountID)
	result = RefreshResult{Token: tokenInfo.AccessToken}
	c.notifyWaiters(accountID, result)
}

// getRefreshFunc 获取刷新函数（支持测试注入）
func (c *TokenRefreshCoordinator) getRefreshFunc() func(ctx context.Context, account *Account) (*AntigravityTokenInfo, error) {
	if c.refreshFunc != nil {
		return c.refreshFunc
	}
	return c.antigravityOAuthService.RefreshAccountToken
}

// getBuildCredentialsFunc 获取构建凭证函数（支持测试注入）
func (c *TokenRefreshCoordinator) getBuildCredentialsFunc() func(tokenInfo *AntigravityTokenInfo) map[string]any {
	if c.buildCredentialsFunc != nil {
		return c.buildCredentialsFunc
	}
	return c.antigravityOAuthService.BuildAccountCredentials
}

// refreshWithRetry 带重试的刷新
func (c *TokenRefreshCoordinator) refreshWithRetry(ctx context.Context, account *Account) (*AntigravityTokenInfo, error) {
	const maxRetries = 3
	var lastErr error
	refreshFn := c.getRefreshFunc()

	for attempt := 1; attempt <= maxRetries; attempt++ {
		tokenInfo, err := refreshFn(ctx, account)
		if err == nil {
			return tokenInfo, nil
		}

		// 不可重试错误，立即返回
		if isNonRetryableAntigravityOAuthError(err) {
			return nil, err
		}

		lastErr = err
		log.Printf("[TokenRefreshCoordinator] Account %d: refresh attempt %d/%d failed: %v",
			account.ID, attempt, maxRetries, err)

		if attempt < maxRetries {
			// 指数退避
			backoff := time.Duration(1<<uint(attempt-1)) * time.Second
			if backoff > 8*time.Second {
				backoff = 8 * time.Second
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
		}
	}

	return nil, fmt.Errorf("refresh failed after %d retries: %w", maxRetries, lastErr)
}

// handleRefreshError 处理刷新失败
func (c *TokenRefreshCoordinator) handleRefreshError(ctx context.Context, account *Account, err error) {
	errMsg := err.Error()
	action := c.determineErrorAction(errMsg)

	switch action {
	case ActionSetError:
		// 不可恢复错误：标记账户为 error 状态
		errorMsg := fmt.Sprintf("OAuth refresh failed: %s", errMsg)
		if setErr := c.accountRepo.SetError(ctx, account.ID, errorMsg); setErr != nil {
			log.Printf("[TokenRefreshCoordinator] Account %d: failed to set error status: %v", account.ID, setErr)
		} else {
			log.Printf("[TokenRefreshCoordinator] Account %d: marked as error due to: %s", account.ID, errMsg)
		}

	case ActionSetRateLimited:
		// 临时错误：设置短期限流状态（5 分钟后重试）
		retryAfter := time.Now().Add(5 * time.Minute)
		if setErr := c.accountRepo.SetRateLimited(ctx, account.ID, retryAfter); setErr != nil {
			log.Printf("[TokenRefreshCoordinator] Account %d: failed to set rate limited: %v", account.ID, setErr)
		} else {
			log.Printf("[TokenRefreshCoordinator] Account %d: rate limited until %v due to: %s",
				account.ID, retryAfter.Format("15:04:05"), errMsg)
		}

	case ActionLogOnly:
		// 未知错误：仅记录日志
		log.Printf("[TokenRefreshCoordinator] Account %d: refresh failed (no action): %s", account.ID, errMsg)
	}
}

// determineErrorAction 根据错误类型决定处理动作
func (c *TokenRefreshCoordinator) determineErrorAction(errMsg string) RefreshErrorAction {
	errMsgLower := strings.ToLower(errMsg)

	// 不可恢复错误（需用户介入）
	nonRetryable := []string{
		"invalid_grant",
		"invalid_client",
		"unauthorized_client",
		"access_denied",
	}
	for _, needle := range nonRetryable {
		if strings.Contains(errMsgLower, needle) {
			return ActionSetError
		}
	}

	// 临时错误（可自动恢复）
	temporary := []string{
		"connection refused",
		"connection reset",
		"timeout",
		"temporary failure",
		"service unavailable",
		"500",
		"502",
		"503",
		"504",
	}
	for _, needle := range temporary {
		if strings.Contains(errMsgLower, needle) {
			return ActionSetRateLimited
		}
	}

	// 未知错误
	return ActionLogOnly
}

// notifyWaiters 通知所有等待者刷新结果
func (c *TokenRefreshCoordinator) notifyWaiters(accountID int64, result RefreshResult) {
	c.mu.Lock()
	waiters := c.inProgress[accountID]
	delete(c.inProgress, accountID)
	c.mu.Unlock()

	for _, ch := range waiters {
		ch <- result
		close(ch)
	}
}
