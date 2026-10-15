package service

import (
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/pkg/devin"
)

func (a *Account) IsDevin() bool { return a != nil && a.Platform == PlatformDevin }

func (a *Account) GetDevinSessionToken() string {
	if !a.IsDevin() || a.Type != AccountTypeOAuth {
		return ""
	}
	return strings.TrimSpace(a.GetCredential("session_token"))
}

func (a *Account) GetDevinBaseURL() string {
	if value := strings.TrimSpace(a.GetCredential("base_url")); value != "" {
		return value
	}
	return devin.DevinDefaultBaseURL
}
