package service

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/pkg/logger"
	"github.com/gin-gonic/gin"
)

func responsesBodyLimit(targetURL string) (int, string) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return 0, "upstream"
	}
	switch strings.ToLower(u.Hostname()) {
	case "api.deepseek.com":
		return 48 << 20, "deepseek_official"
	case "commandcode-proxy":
		return 20 << 20, "commandcode_proxy_local"
	default:
		return 0, "upstream"
	}
}

func writeResponsesBodyTooLarge(c *gin.Context, targetURL string, bodyBytes int64) error {
	limit, source := responsesBodyLimit(targetURL)
	message := "Request body exceeds the upstream request size limit"
	if limit > 0 {
		message = fmt.Sprintf("Request body exceeds %s limit (%d bytes)", source, limit)
	}
	if c != nil {
		MarkResponseCommitted(c)
		if StopOpenAICompactSSEKeepaliveCommitted(c) {
			writeOpenAICompactSSEFailureMessageParam(c, 413, "request_body_too_large", message, "")
		} else {
			c.JSON(413, gin.H{"error": gin.H{"type": "invalid_request_error", "code": "request_body_too_large", "message": message, "limit_source": source, "limit_bytes": limit, "request_bytes": bodyBytes}})
		}
	}
	return fmt.Errorf("request_body_too_large: %s", message)
}

func checkResponsesRequestSize(c *gin.Context, account *Account, targetURL string, ingressBytes int, body []byte) error {
	limit, source := responsesBodyLimit(targetURL)
	requestID := ""
	if c != nil {
		requestID = c.GetString("request_id")
	}
	logger.LegacyPrintf("service.openai_request_size", "request_size request_id=%s account_id=%d route=responses limit_source=%s limit_bytes=%d ingress_bytes=%d egress_bytes=%d images=%d", requestID, account.ID, source, limit, ingressBytes, len(body), responsesImageCount(body))
	if limit > 0 && len(body) > limit {
		return writeResponsesBodyTooLarge(c, targetURL, int64(len(body)))
	}
	return nil
}
