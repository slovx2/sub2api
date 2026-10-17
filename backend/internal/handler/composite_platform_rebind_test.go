package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// composite 多平台候选：选中账号后目标平台跟随账号平台。
func TestSetOpsSelectedAccountRebindsCompositeCandidatePlatform(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	c.Request = c.Request.WithContext(service.WithCompositeRouteDecision(c.Request.Context(), service.CompositeRouteDecision{
		Matched: true, Source: service.CompositeRouteSourceAccount, PublicModel: "deepseek-flash",
		TargetPlatform: service.PlatformDeepseek, UpstreamModel: "deepseek-flash",
		CandidatePlatforms: []string{service.PlatformDeepseek, service.PlatformOpenCodeGo},
	}))

	setOpsSelectedAccount(c, 386, service.PlatformOpenCodeGo)
	platform, ok := service.ResolvedTargetPlatformFromContext(c.Request.Context())
	require.True(t, ok)
	require.Equal(t, service.PlatformOpenCodeGo, platform)

	setOpsSelectedAccount(c, 376, service.PlatformDeepseek)
	platform, _ = service.ResolvedTargetPlatformFromContext(c.Request.Context())
	require.Equal(t, service.PlatformDeepseek, platform)
}

// 单平台解析结果不受选中账号平台影响。
func TestSetOpsSelectedAccountKeepsSingleCompositePlatform(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	c.Request = c.Request.WithContext(service.WithResolvedTargetPlatform(c.Request.Context(), service.PlatformDeepseek))

	setOpsSelectedAccount(c, 386, service.PlatformOpenCodeGo)
	platform, _ := service.ResolvedTargetPlatformFromContext(c.Request.Context())
	require.Equal(t, service.PlatformDeepseek, platform)
}
