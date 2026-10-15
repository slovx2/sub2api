package admin

import (
	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

type DevinOAuthHandler struct{ devinOAuthService *service.DevinOAuthService }

func NewDevinOAuthHandler(s *service.DevinOAuthService) *DevinOAuthHandler {
	return &DevinOAuthHandler{devinOAuthService: s}
}

func (h *DevinOAuthHandler) DevinAuthURL(c *gin.Context) {
	var req struct {
		ProxyID *int64 `json:"proxy_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid request")
		return
	}
	result, err := h.devinOAuthService.GenerateAuthURL(c.Request.Context(), req.ProxyID)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, result)
}

func (h *DevinOAuthHandler) DevinExchangeCode(c *gin.Context) {
	var req struct {
		SessionID string `json:"session_id" binding:"required"`
		Code      string `json:"code" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid request")
		return
	}
	result, err := h.devinOAuthService.ExchangeCode(c.Request.Context(), req.SessionID, req.Code)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	c.Header("Cache-Control", "no-store")
	response.Success(c, result)
}
