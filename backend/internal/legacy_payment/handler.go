package legacy_payment

import (
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/gin-gonic/gin"
)

type Handler struct {
	service *Service
}

func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

type createOrderRequest struct {
	Amount  int64  `json:"amount" binding:"required,gt=0"`
	Channel string `json:"channel" binding:"required,oneof=alipay wxpay"`
	Device  string `json:"device" binding:"omitempty,oneof=pc mobile qq wechat alipay"`
}

type createOrderResponse struct {
	ID      int64  `json:"id"`
	OrderNo string `json:"order_no"`
	Status  string `json:"status"`
	Amount  int64  `json:"amount"`
	Channel string `json:"channel"`
	PayType string `json:"pay_type"`
	PayInfo string `json:"pay_info"`
}

type orderStatusResponse struct {
	ID         int64   `json:"id"`
	OrderNo    string  `json:"order_no"`
	Status     string  `json:"status"`
	Amount     int64   `json:"amount"`
	Channel    string  `json:"channel"`
	PayType    string  `json:"pay_type"`
	PayInfo    string  `json:"pay_info"`
	CreatedAt  string  `json:"created_at"`
	PaidAt     *string `json:"paid_at,omitempty"`
	CreditedAt *string `json:"credited_at,omitempty"`
}

func (h *Handler) CreateOrder(c *gin.Context) {
	subject, ok := middleware.GetAuthSubjectFromContext(c)
	if !ok {
		response.Unauthorized(c, "Unauthorized")
		return
	}

	var req createOrderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid request: "+err.Error())
		return
	}

	result, err := h.service.CreateOrder(c.Request.Context(), CreateOrderRequest{
		UserID:   subject.UserID,
		Amount:   req.Amount,
		Channel:  req.Channel,
		Device:   req.Device,
		ClientIP: c.ClientIP(),
	})
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}

	resp := createOrderResponse{
		ID:      result.Order.ID,
		OrderNo: result.Order.OrderNo,
		Status:  result.Order.Status,
		Amount:  result.Order.AmountCNY,
		Channel: result.Order.Channel,
		PayType: result.PayType,
		PayInfo: result.PayInfo,
	}
	response.Success(c, resp)
}

func (h *Handler) GetConfig(c *gin.Context) {
	cfg := h.service.PublicConfig()
	if h.service == nil || h.service.cfg == nil {
		log.Printf("legacy payment config requested: enabled=%t min=%d max=%d step=%d cfg=nil", cfg.Enabled, cfg.MinAmount, cfg.MaxAmount, cfg.Step)
		response.Success(c, cfg)
		return
	}
	raw := h.service.cfg
	log.Printf(
		"legacy payment config requested: enabled=%t min=%d max=%d step=%d public_base_url=%t merchant_id=%d private_key_len=%d public_key_len=%d",
		cfg.Enabled,
		cfg.MinAmount,
		cfg.MaxAmount,
		cfg.Step,
		strings.TrimSpace(raw.PublicBaseURL) != "",
		raw.PluginsWorld.MerchantID,
		len(strings.TrimSpace(raw.PluginsWorld.MerchantPrivateKey)),
		len(strings.TrimSpace(raw.PluginsWorld.PlatformPublicKey)),
	)
	response.Success(c, cfg)
}

func (h *Handler) GetOrder(c *gin.Context) {
	subject, ok := middleware.GetAuthSubjectFromContext(c)
	if !ok {
		response.Unauthorized(c, "Unauthorized")
		return
	}

	orderID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || orderID <= 0 {
		response.BadRequest(c, "Invalid order ID")
		return
	}

	result, err := h.service.GetOrder(c.Request.Context(), subject.UserID, orderID)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}

	response.Success(c, formatOrderStatusResponse(result))
}

func (h *Handler) ListOrders(c *gin.Context) {
	subject, ok := middleware.GetAuthSubjectFromContext(c)
	if !ok {
		response.Unauthorized(c, "Unauthorized")
		return
	}

	page, pageSize := response.ParsePagination(c)
	orders, total, err := h.service.ListOrders(c.Request.Context(), subject.UserID, page, pageSize)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}

	items := make([]orderStatusResponse, 0, len(orders))
	for _, order := range orders {
		items = append(items, formatOrderStatusResponse(&OrderStatusResult{
			ID:         order.ID,
			OrderNo:    order.OrderNo,
			Status:     order.Status,
			Amount:     order.AmountCNY,
			Channel:    order.Channel,
			PayType:    order.PayType,
			PayInfo:    order.PayInfo,
			CreatedAt:  order.CreatedAt,
			PaidAt:     order.PaidAt,
			CreditedAt: order.CreditedAt,
		}))
	}

	response.Paginated(c, items, total, page, pageSize)
}

func (h *Handler) Notify(c *gin.Context) {
	params := make(map[string]string)
	for key, values := range c.Request.URL.Query() {
		if len(values) == 0 {
			continue
		}
		params[key] = values[0]
	}

	if err := h.service.HandleNotify(c.Request.Context(), params, c.Request.URL.RawQuery); err != nil {
		log.Printf("legacy payment notify failed: %v", err)
		c.String(http.StatusBadRequest, "fail")
		return
	}
	c.String(http.StatusOK, "success")
}

func (h *Handler) Return(c *gin.Context) {
	c.Redirect(http.StatusFound, "/recharge?paid=1")
}

const timeFormat = "2006-01-02 15:04:05"

func formatOrderStatusResponse(result *OrderStatusResult) orderStatusResponse {
	if result == nil {
		return orderStatusResponse{}
	}
	resp := orderStatusResponse{
		ID:        result.ID,
		OrderNo:   result.OrderNo,
		Status:    result.Status,
		Amount:    result.Amount,
		Channel:   result.Channel,
		PayType:   result.PayType,
		PayInfo:   result.PayInfo,
		CreatedAt: result.CreatedAt.Format(timeFormat),
	}
	if result.PaidAt != nil {
		val := result.PaidAt.Format(timeFormat)
		resp.PaidAt = &val
	}
	if result.CreditedAt != nil {
		val := result.CreditedAt.Format(timeFormat)
		resp.CreditedAt = &val
	}
	return resp
}
