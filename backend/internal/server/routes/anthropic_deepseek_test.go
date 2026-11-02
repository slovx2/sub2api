package routes

import (
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
		{"other endpoint", "anthropic", "/v1/responses", "deepseek-flash", "anthropic"},
		{"other group", "gemini", "/v1/messages", "deepseek-flash", "gemini"},
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
			router.Use(compositeTargetPlatformMiddleware(nil))
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
