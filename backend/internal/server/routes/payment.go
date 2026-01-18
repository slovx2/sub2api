package routes

import (
	"database/sql"
	"log"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/payment"
	"github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"

	"github.com/gin-gonic/gin"
)

func RegisterPaymentRoutes(v1 *gin.RouterGroup, db *sql.DB, adminService service.AdminService, jwtAuth middleware.JWTAuthMiddleware) {
	if db == nil || adminService == nil {
		log.Printf("payment routes disabled: missing dependencies")
		return
	}

	cfg, err := payment.LoadConfig()
	if err != nil {
		log.Printf("payment config load failed: %v", err)
		cfg = payment.DefaultConfig()
		cfg.Enabled = false
	}
	if cfg == nil {
		cfg = payment.DefaultConfig()
	}
	log.Printf(
		"payment config loaded: enabled=%t min=%d max=%d step=%d public_base_url=%t merchant_id=%d private_key_len=%d public_key_len=%d",
		cfg.Enabled,
		cfg.MinAmount,
		cfg.MaxAmount,
		cfg.Step,
		strings.TrimSpace(cfg.PublicBaseURL) != "",
		cfg.PluginsWorld.MerchantID,
		len(strings.TrimSpace(cfg.PluginsWorld.MerchantPrivateKey)),
		len(strings.TrimSpace(cfg.PluginsWorld.PlatformPublicKey)),
	)
	provider, err := payment.NewPluginsWorldProvider(cfg)
	if err != nil {
		log.Printf("payment provider init failed: %v", err)
		cfg.Enabled = false
		provider, _ = payment.NewPluginsWorldProvider(cfg)
	}

	paymentService := payment.NewService(cfg, payment.NewOrderRepository(db), provider, adminService)
	handler := payment.NewHandler(paymentService)

	payments := v1.Group("/payments")
	{
		payments.GET("/config", handler.GetConfig)
		payments.GET("/notify", handler.Notify)
		payments.GET("/return", handler.Return)
	}

	secured := v1.Group("/payments")
	secured.Use(gin.HandlerFunc(jwtAuth))
	{
		secured.POST("/orders", handler.CreateOrder)
		secured.GET("/orders", handler.ListOrders)
		secured.GET("/orders/:id", handler.GetOrder)
	}
}
