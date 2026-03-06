//go:build unit

package service

import (
	"context"
	"net/http"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/stretchr/testify/require"
)

func TestRateLimitService_HandleUpstreamError_OpenAI403Retryable(t *testing.T) {
	tests := []struct {
		name         string
		accountType  string
		responseBody []byte
		wantDisable  bool
		wantSetError int
	}{
		{
			name:        "forbidden permission message",
			accountType: AccountTypeAPIKey,
			responseBody: []byte(`{
				"error": {
					"message": "Account may be suspended or lack permissions"
				}
			}`),
			wantDisable:  false,
			wantSetError: 0,
		},
		{
			name:         "empty upstream body should still mark error",
			accountType:  AccountTypeOAuth,
			responseBody: nil,
			wantDisable:  true,
			wantSetError: 1,
		},
		{
			name:        "other forbidden message should still mark error",
			accountType: AccountTypeAPIKey,
			responseBody: []byte(`{
				"error": {
					"message": "Forbidden by upstream policy"
				}
			}`),
			wantDisable:  true,
			wantSetError: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &rateLimitAccountRepoStub{}
			service := NewRateLimitService(repo, nil, &config.Config{}, nil, nil)
			account := &Account{
				ID:       201,
				Platform: PlatformOpenAI,
				Type:     tt.accountType,
			}

			shouldDisable := service.HandleUpstreamError(context.Background(), account, http.StatusForbidden, http.Header{}, tt.responseBody)

			require.Equal(t, tt.wantDisable, shouldDisable)
			require.Equal(t, tt.wantSetError, repo.setErrorCalls)
			require.Equal(t, 0, repo.tempCalls)
		})
	}
}

func TestRateLimitService_HandleUpstreamError_NonOpenAI403StillSetsError(t *testing.T) {
	repo := &rateLimitAccountRepoStub{}
	service := NewRateLimitService(repo, nil, &config.Config{}, nil, nil)
	account := &Account{
		ID:       202,
		Platform: PlatformGemini,
		Type:     AccountTypeOAuth,
	}

	shouldDisable := service.HandleUpstreamError(context.Background(), account, http.StatusForbidden, http.Header{}, nil)

	require.True(t, shouldDisable)
	require.Equal(t, 1, repo.setErrorCalls)
	require.Contains(t, repo.lastErrorMsg, "Access forbidden (403)")
}
