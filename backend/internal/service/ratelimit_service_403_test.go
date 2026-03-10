//go:build unit

package service

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/stretchr/testify/require"
)

func TestRateLimitService_HandleUpstreamError_403RetriesBlockedOpenAIMessage(t *testing.T) {
	repo := &rateLimitAccountRepoStub{}
	service := NewRateLimitService(repo, nil, &config.Config{}, nil, nil)
	account := &Account{
		ID:       200,
		Platform: PlatformOpenAI,
		Type:     AccountTypeOAuth,
	}

	shouldDisable := service.HandleUpstreamError(
		context.Background(),
		account,
		http.StatusForbidden,
		http.Header{},
		[]byte(`{"error":{"message":"Your request was blocked."}}`),
	)

	require.False(t, shouldDisable)
	require.Zero(t, repo.setErrorCalls)
	require.Empty(t, repo.lastErrorMsg)
}

func TestRateLimitService_HandleUpstreamError_403RetriesBlockedOpenAIRawBody(t *testing.T) {
	repo := &rateLimitAccountRepoStub{}
	service := NewRateLimitService(repo, nil, &config.Config{}, nil, nil)
	account := &Account{
		ID:       206,
		Platform: PlatformOpenAI,
		Type:     AccountTypeOAuth,
	}

	shouldDisable := service.HandleUpstreamError(
		context.Background(),
		account,
		http.StatusForbidden,
		http.Header{},
		[]byte("Your request was blocked."),
	)

	require.False(t, shouldDisable)
	require.Zero(t, repo.setErrorCalls)
	require.Empty(t, repo.lastErrorMsg)
}

func TestRateLimitService_HandleUpstreamError_403RecordsExtractedMessage(t *testing.T) {
	repo := &rateLimitAccountRepoStub{}
	service := NewRateLimitService(repo, nil, &config.Config{}, nil, nil)
	account := &Account{
		ID:       201,
		Platform: PlatformOpenAI,
		Type:     AccountTypeOAuth,
	}

	shouldDisable := service.HandleUpstreamError(
		context.Background(),
		account,
		http.StatusForbidden,
		http.Header{},
		[]byte(`{"error":{"message":"Forbidden by org policy"}}`),
	)

	require.True(t, shouldDisable)
	require.Equal(t, 1, repo.setErrorCalls)
	require.Equal(t, "Access forbidden (403): Forbidden by org policy", repo.lastErrorMsg)
}

func TestRateLimitService_HandleUpstreamError_403StillSetsErrorForNonOpenAIBlockedMessage(t *testing.T) {
	repo := &rateLimitAccountRepoStub{}
	service := NewRateLimitService(repo, nil, &config.Config{}, nil, nil)
	account := &Account{
		ID:       205,
		Platform: PlatformAnthropic,
		Type:     AccountTypeOAuth,
	}

	shouldDisable := service.HandleUpstreamError(
		context.Background(),
		account,
		http.StatusForbidden,
		http.Header{},
		[]byte(`{"error":{"message":"Your request was blocked."}}`),
	)

	require.True(t, shouldDisable)
	require.Equal(t, 1, repo.setErrorCalls)
	require.Equal(t, "Access forbidden (403): Your request was blocked.", repo.lastErrorMsg)
}

func TestRateLimitService_HandleUpstreamError_403RecordsRawBodyWhenMessageEmpty(t *testing.T) {
	repo := &rateLimitAccountRepoStub{}
	service := NewRateLimitService(repo, nil, &config.Config{}, nil, nil)
	account := &Account{
		ID:       202,
		Platform: PlatformOpenAI,
		Type:     AccountTypeOAuth,
	}

	rawBody := `{"error":{"code":"forbidden","detail":"blocked by upstream"}}`
	shouldDisable := service.HandleUpstreamError(
		context.Background(),
		account,
		http.StatusForbidden,
		http.Header{},
		[]byte(rawBody),
	)

	require.True(t, shouldDisable)
	require.Equal(t, 1, repo.setErrorCalls)
	require.Equal(t, "Access forbidden (403): "+rawBody, repo.lastErrorMsg)
}

func TestRateLimitService_HandleUpstreamError_403RecordsTruncatedRawBodyWhenMessageEmpty(t *testing.T) {
	repo := &rateLimitAccountRepoStub{}
	service := NewRateLimitService(repo, nil, &config.Config{}, nil, nil)
	account := &Account{
		ID:       203,
		Platform: PlatformOpenAI,
		Type:     AccountTypeOAuth,
	}

	rawBody := strings.Repeat("a", 1200)
	shouldDisable := service.HandleUpstreamError(
		context.Background(),
		account,
		http.StatusForbidden,
		http.Header{},
		[]byte(rawBody),
	)

	require.True(t, shouldDisable)
	require.Equal(t, 1, repo.setErrorCalls)
	require.Equal(t, "Access forbidden (403): "+strings.Repeat("a", 1024), repo.lastErrorMsg)
}

func TestRateLimitService_HandleUpstreamError_403FallsBackWhenBodyEmpty(t *testing.T) {
	repo := &rateLimitAccountRepoStub{}
	service := NewRateLimitService(repo, nil, &config.Config{}, nil, nil)
	account := &Account{
		ID:       204,
		Platform: PlatformOpenAI,
		Type:     AccountTypeOAuth,
	}

	shouldDisable := service.HandleUpstreamError(
		context.Background(),
		account,
		http.StatusForbidden,
		http.Header{},
		nil,
	)

	require.True(t, shouldDisable)
	require.Equal(t, 1, repo.setErrorCalls)
	require.Equal(t, "Access forbidden (403): account may be suspended or lack permissions", repo.lastErrorMsg)
}
