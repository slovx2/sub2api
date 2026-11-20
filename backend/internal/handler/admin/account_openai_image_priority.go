package admin

import (
	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

// OpenAIImagePriorityAccountItem 是图片优先账号列表中单个账号的精简视图。
type OpenAIImagePriorityAccountItem struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Status      string `json:"status"`
	Schedulable bool   `json:"schedulable"`
	Priority    int    `json:"priority"`
	Concurrency int    `json:"concurrency"`
}

// OpenAIImagePriorityAccountsResponse 返回配置的账号 ID（含已删除账号）及仍存在账号的详情。
type OpenAIImagePriorityAccountsResponse struct {
	AccountIDs []int64                          `json:"account_ids"`
	Accounts   []OpenAIImagePriorityAccountItem `json:"accounts"`
}

type UpdateOpenAIImagePriorityAccountsRequest struct {
	AccountIDs []int64 `json:"account_ids"`
}

func toOpenAIImagePriorityAccountsResponse(value *service.OpenAIImagePriorityAccounts) OpenAIImagePriorityAccountsResponse {
	resp := OpenAIImagePriorityAccountsResponse{
		AccountIDs: []int64{},
		Accounts:   []OpenAIImagePriorityAccountItem{},
	}
	if value == nil {
		return resp
	}
	if value.AccountIDs != nil {
		resp.AccountIDs = value.AccountIDs
	}
	for _, account := range value.Accounts {
		if account == nil {
			continue
		}
		resp.Accounts = append(resp.Accounts, OpenAIImagePriorityAccountItem{
			ID:          account.ID,
			Name:        account.Name,
			Type:        account.Type,
			Status:      account.Status,
			Schedulable: account.Schedulable,
			Priority:    account.Priority,
			Concurrency: account.Concurrency,
		})
	}
	return resp
}

// GetOpenAIImagePriorityAccounts 获取全局图片优先 OpenAI 账号
// GET /api/v1/admin/accounts/openai-image-priority
func (h *AccountHandler) GetOpenAIImagePriorityAccounts(c *gin.Context) {
	value, err := h.adminService.GetOpenAIImagePriorityAccounts(c.Request.Context())
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, toOpenAIImagePriorityAccountsResponse(value))
}

// UpdateOpenAIImagePriorityAccounts 覆盖保存全局图片优先 OpenAI 账号
// PUT /api/v1/admin/accounts/openai-image-priority
func (h *AccountHandler) UpdateOpenAIImagePriorityAccounts(c *gin.Context) {
	var req UpdateOpenAIImagePriorityAccountsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid request: "+err.Error())
		return
	}
	value, err := h.adminService.UpdateOpenAIImagePriorityAccounts(c.Request.Context(), req.AccountIDs)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, toOpenAIImagePriorityAccountsResponse(value))
}
