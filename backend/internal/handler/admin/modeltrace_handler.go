package admin

import (
	"github.com/Wei-Shaw/sub2api/internal/pkg/modeltrace"
	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

func (h *AccountHandler) SetModelTraceService(s *service.ModelTraceService) { h.modeltrace = s }
func (h *AccountHandler) GetModelTraceSettings(c *gin.Context) {
	cfg, err := h.modeltrace.Settings(c.Request.Context())
	if err != nil {
		response.InternalError(c, "读取探测配置失败")
		return
	}
	accounts, err := h.modeltrace.Accounts(c.Request.Context())
	if err != nil {
		response.InternalError(c, "读取账号列表失败")
		return
	}
	response.Success(c, gin.H{"config": cfg, "accounts": accounts, "candidates": modeltrace.Models(), "bank_version": modeltrace.Version()})
}
func (h *AccountHandler) SaveModelTraceSettings(c *gin.Context) {
	var cfg service.ModelTraceSettings
	if err := c.ShouldBindJSON(&cfg); err != nil {
		response.BadRequest(c, "配置格式无效")
		return
	}
	if err := cfg.Validate(); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	if err := h.modeltrace.SaveSettings(c.Request.Context(), cfg); err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	response.Success(c, cfg)
}
func (h *AccountHandler) RunModelTrace(c *gin.Context) {
	result, err := h.modeltrace.RunNow(c.Request.Context())
	if err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	response.Success(c, result)
}
