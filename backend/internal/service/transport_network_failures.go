package service

import (
	"net/http"
	"sync"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/tlsfingerprint"
)

const proxyAuthTransportCooldown = 10 * time.Minute

// 三套转发服务共享一个 RateLimitService。计数只在本进程保留；
// 达到阈值后用既有账号状态写入冷却，其他实例也能看到。
type upstreamTransportFailures struct {
	mu       sync.Mutex
	accounts map[int64]upstreamTransportFailureStreak
}

type upstreamTransportFailureStreak struct {
	failures     int
	coolingUntil time.Time
}

func (s *upstreamTransportFailures) fail(accountID int64, threshold int, cooldown time.Duration, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	streak := s.accounts[accountID]
	if now.Before(streak.coolingUntil) {
		return false
	}
	streak.failures++
	tripped := streak.failures >= threshold
	if tripped {
		streak = upstreamTransportFailureStreak{coolingUntil: now.Add(cooldown)}
	}
	if s.accounts == nil {
		s.accounts = make(map[int64]upstreamTransportFailureStreak)
	}
	s.accounts[accountID] = streak
	return tripped
}

func (s *RateLimitService) upstreamTransportCooldown(accountID int64, err error) time.Duration {
	switch classifyUpstreamTransportError(err) {
	case upstreamTransportProxyAuth:
		return proxyAuthTransportCooldown
	case upstreamTransportNetwork:
		if s == nil || accountID <= 0 {
			return 0
		}
		threshold, cooldown := config.DefaultTransportNetworkFailureThreshold, config.DefaultTransportNetworkFailureCooldown
		if s.cfg != nil {
			if configured := s.cfg.Gateway.Scheduling.TransportNetworkFailureThreshold; configured >= 2 {
				threshold = configured
			}
			if configured := s.cfg.Gateway.Scheduling.TransportNetworkFailureCooldown; configured > 0 {
				cooldown = configured
			}
		}
		if s.transportFailures.fail(accountID, threshold, cooldown, time.Now()) {
			return cooldown
		}
	}
	return 0
}

func (s *RateLimitService) resetUpstreamTransportFailures(accountID int64) {
	if s == nil || accountID <= 0 {
		return
	}
	s.transportFailures.mu.Lock()
	delete(s.transportFailures.accounts, accountID)
	s.transportFailures.mu.Unlock()
}

func (s *RateLimitService) observeUpstreamTransportResponse(accountID int64, resp *http.Response, err error) {
	// HTTP 错误仍证明连接已建立，其账号级处置留给原来的 HTTP 错误路径。
	if err == nil && resp != nil && resp.StatusCode != http.StatusProxyAuthRequired {
		s.resetUpstreamTransportFailures(accountID)
	}
}

// 仅挂在三套真实转发服务上；后台探测与刷新请求不打断转发失败的计数。
type transportRecoveryHTTPUpstream struct {
	upstream HTTPUpstream
	tracker  *RateLimitService
}

func withTransportRecovery(upstream HTTPUpstream, tracker *RateLimitService) HTTPUpstream {
	if upstream == nil || tracker == nil {
		return upstream
	}
	return transportRecoveryHTTPUpstream{upstream: upstream, tracker: tracker}
}

func (u transportRecoveryHTTPUpstream) Do(req *http.Request, proxyURL string, accountID int64, concurrency int) (*http.Response, error) {
	resp, err := u.upstream.Do(req, proxyURL, accountID, concurrency)
	u.tracker.observeUpstreamTransportResponse(accountID, resp, err)
	return resp, err
}

func (u transportRecoveryHTTPUpstream) DoWithTLS(req *http.Request, proxyURL string, accountID int64, concurrency int, profile *tlsfingerprint.Profile) (*http.Response, error) {
	resp, err := u.upstream.DoWithTLS(req, proxyURL, accountID, concurrency, profile)
	u.tracker.observeUpstreamTransportResponse(accountID, resp, err)
	return resp, err
}
