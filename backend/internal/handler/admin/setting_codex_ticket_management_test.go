package admin

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestCodexTicketManagementQueryValidation(t *testing.T) {
	h := &SettingHandler{}
	for _, handler := range []gin.HandlerFunc{h.GetCodexTicketLogs, h.GetCodexTicketOverview} {
		for _, query := range []string{"page=-1", "page=1000001", "page_size=101", "account_id=-1", "result=unknown", "problems_only=wrong"} {
			rec := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(rec)
			ctx.Request = httptest.NewRequest(http.MethodGet, "/?"+query, nil)
			handler(ctx)
			require.Equal(t, http.StatusBadRequest, rec.Code, query)
		}
	}
}

func TestCodexTicketManagementDisabledOverview(t *testing.T) {
	h := &SettingHandler{}
	h.SetCodexTicketGateway(&service.OpenAIGatewayService{})
	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	h.GetCodexTicketOverview(ctx)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), `"enabled":false`)
	require.Contains(t, rec.Body.String(), `"items":[]`)
}
