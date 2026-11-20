package routes

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// 模拟组内账号映射：glm-5.3 仅由 DeepSeek 账号声明；shared-model 同时被
// anthropic 账号声明；claude-opus-5-5 被 DeepSeek 账号映射（不应抢走 Claude 流量）。
func testAnthropicGroupOwnershipResolver() *service.CompositeRouteResolver {
	resolver := service.NewCompositeRouteResolver(nil)
	resolver.SetModelOwnershipResolver(func(_ context.Context, groupID int64, model string) (service.CompositeModelOwnership, error) {
		if groupID != 71 {
			return service.CompositeModelOwnership{}, nil
		}
		switch model {
		case "glm-5.3", "claude-opus-5-5":
			return service.CompositeModelOwnership{TargetPlatform: service.PlatformDeepseek, Matched: true, Platforms: []string{service.PlatformDeepseek}}, nil
		case "shared-model":
			return service.CompositeModelOwnership{Ambiguous: true, Platforms: []string{service.PlatformAnthropic, service.PlatformDeepseek}}, nil
		case "broken-model":
			return service.CompositeModelOwnership{}, errors.New("account repo unavailable")
		}
		return service.CompositeModelOwnership{}, nil
	})
	return resolver
}

func TestAnthropicGroupDeepseekRouting(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tc := range []struct {
		name, groupPlatform, path, model, wantPlatform string
	}{
		{"messages", "anthropic", "/v1/messages", "deepseek-flash", "deepseek"},
		{"count tokens", "anthropic", "/v1/messages/count_tokens", "deepseek-flash", "deepseek"},
		{"context suffix", "anthropic", "/v1/messages", "deepseek-flash[1m]", "deepseek"},
		{"claude", "anthropic", "/v1/messages", "claude-opus-5-5", "anthropic"},
		{"other provider", "anthropic", "/v1/messages", "gpt-5.5", "anthropic"},
		{"mapped by deepseek account", "anthropic", "/v1/messages", "glm-5.3", "deepseek"},
		{"mapped count tokens", "anthropic", "/v1/messages/count_tokens", "glm-5.3", "deepseek"},
		{"also mapped by anthropic account", "anthropic", "/v1/messages", "shared-model", "anthropic"},
		{"other endpoint", "anthropic", "/v1/responses", "deepseek-flash", "anthropic"},
		{"other group", "gemini", "/v1/messages", "deepseek-flash", "gemini"},
		{"other group mapped model", "gemini", "/v1/messages", "glm-5.3", "gemini"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			groupID := int64(71)
			key := &service.APIKey{GroupID: &groupID, Group: &service.Group{ID: groupID, Platform: tc.groupPlatform}}
			body := `{"model":"` + tc.model + `","messages":[{"role":"user","content":"hello"}],"stream":true}`
			router := gin.New()
			router.Use(func(c *gin.Context) {
				c.Set(string(middleware.ContextKeyAPIKey), key)
				c.Next()
			})
			router.Use(compositeTargetPlatformMiddleware(testAnthropicGroupOwnershipResolver()))
			router.POST(tc.path, func(c *gin.Context) {
				require.Equal(t, tc.wantPlatform, getGroupPlatform(c))
				// 分流只改变请求目标，选号与计费仍使用原分组。
				require.Equal(t, int64(71), *key.GroupID)
				require.Equal(t, tc.groupPlatform, key.Group.Platform)
				got, err := io.ReadAll(c.Request.Body)
				require.NoError(t, err)
				require.Equal(t, body, string(got))
				c.Status(http.StatusNoContent)
			})
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			router.ServeHTTP(w, r)
			require.Equal(t, http.StatusNoContent, w.Code)
		})
	}
}

func TestAnthropicGroupDeepseekRoutingOwnershipError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	groupID := int64(71)
	key := &service.APIKey{GroupID: &groupID, Group: &service.Group{ID: groupID, Platform: service.PlatformAnthropic}}
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set(string(middleware.ContextKeyAPIKey), key)
		c.Next()
	})
	router.Use(compositeTargetPlatformMiddleware(testAnthropicGroupOwnershipResolver()))
	router.POST("/v1/messages", func(c *gin.Context) {
		t.Fatal("handler must not run when model ownership cannot be resolved")
	})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(`{"model":"broken-model","messages":[]}`))
	r.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, r)
	require.Equal(t, http.StatusInternalServerError, w.Code)
}
