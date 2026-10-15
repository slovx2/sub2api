package service

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/Wei-Shaw/sub2api/internal/pkg/devin"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func (s *AccountTestService) testDevinAccountConnection(c *gin.Context, account *Account, model, prompt string) error {
	if model == "" {
		model = "swe-2"
	}
	if prompt == "" {
		prompt = "Reply OK."
	}
	model = account.GetMappedModel(model)
	body, _ := json.Marshal(map[string]any{"model": model, "messages": []any{map[string]string{"role": "user", "content": prompt}}, "max_tokens": 128})
	baseURL, err := s.validateUpstreamBaseURL(account.GetDevinBaseURL())
	if err != nil {
		return s.sendErrorAndEnd(c, "Invalid Devin base URL")
	}
	if account.GetDevinSessionToken() == "" {
		return s.sendErrorAndEnd(c, "Devin session token is missing")
	}
	req, err := devin.NewChatRequest(c.Request.Context(), baseURL, account.GetDevinSessionToken(), uuid.NewString(), body)
	if err != nil {
		return s.sendErrorAndEnd(c, err.Error())
	}
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("X-Accel-Buffering", "no")
	s.sendEvent(c, TestEvent{Type: "test_start", Model: model})
	proxyURL := ""
	if account.ProxyID != nil && account.Proxy != nil {
		proxyURL = account.Proxy.URL()
	}
	resp, err := s.httpUpstream.Do(req, proxyURL, account.ID, account.Concurrency)
	if err != nil {
		return s.sendErrorAndEnd(c, "Failed to contact Devin")
	}
	resp, err = devin.ConvertChatResponse(resp, model, false)
	if err != nil {
		return s.sendErrorAndEnd(c, err.Error())
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return s.sendErrorAndEnd(c, fmt.Sprintf("Devin returned HTTP %d", resp.StatusCode))
	}
	var response struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&response); err != nil {
		return s.sendErrorAndEnd(c, "Invalid Devin response")
	}
	if len(response.Choices) > 0 {
		s.sendEvent(c, TestEvent{Type: "content", Text: response.Choices[0].Message.Content})
	}
	s.sendEvent(c, TestEvent{Type: "test_complete", Success: true})
	return nil
}
