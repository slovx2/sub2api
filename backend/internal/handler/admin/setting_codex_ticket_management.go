package admin

import (
	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

func (h *SettingHandler) SetCodexTicketGateway(gateway *service.OpenAIGatewayService) {
	h.codexTicketGateway = gateway
}

type codexTicketQuery struct {
	Page         int    `form:"page" binding:"omitempty,min=1,max=1000000"`
	PageSize     int    `form:"page_size" binding:"omitempty,min=1,max=100"`
	AccountID    int64  `form:"account_id" binding:"omitempty,min=1"`
	Result       string `form:"result" binding:"omitempty,oneof=success failure injection_missing"`
	ProblemsOnly bool   `form:"problems_only"`
}

func (h *SettingHandler) GetCodexTicketOverview(c *gin.Context) {
	var q codexTicketQuery
	if err := c.ShouldBindQuery(&q); err != nil {
		response.BadRequest(c, "无效的打票查询参数")
		return
	}
	if h.codexTicketGateway == nil {
		response.Error(c, 503, "打票管理尚未初始化")
		return
	}
	data, err := h.codexTicketGateway.CodexTicketOverview(c.Request.Context(), q.Page, q.PageSize, q.ProblemsOnly)
	if err != nil {
		response.Error(c, 500, "读取票据总览失败")
		return
	}
	response.Success(c, data)
}

func (h *SettingHandler) GetCodexTicketLogs(c *gin.Context) {
	var q codexTicketQuery
	if err := c.ShouldBindQuery(&q); err != nil {
		response.BadRequest(c, "无效的打票查询参数")
		return
	}
	if h.codexTicketGateway == nil {
		response.Error(c, 503, "打票管理尚未初始化")
		return
	}
	data, err := h.codexTicketGateway.ListCodexTicketLogs(c.Request.Context(), service.CodexTicketLogFilter{Page: q.Page, PageSize: q.PageSize, AccountID: q.AccountID, Result: q.Result})
	if err != nil {
		response.Error(c, 500, "读取打票日志失败")
		return
	}
	response.Success(c, data)
}
