package service

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/stretchr/testify/require"
)

func TestCodexTicketPolicyValidation(t *testing.T) {
	base := CodexTicketPolicy{TTLSeconds: 3600, RefreshBeforeSeconds: 600, MaxAttempts: 3, FailureCooldownSeconds: 3600}
	require.NoError(t, base.Validate())
	for _, modify := range []func(*CodexTicketPolicy){
		func(p *CodexTicketPolicy) { p.TTLSeconds = 59 }, func(p *CodexTicketPolicy) { p.TTLSeconds = 86401 },
		func(p *CodexTicketPolicy) { p.RefreshBeforeSeconds = -1 }, func(p *CodexTicketPolicy) { p.RefreshBeforeSeconds = 3600 },
		func(p *CodexTicketPolicy) { p.MaxAttempts = 0 }, func(p *CodexTicketPolicy) { p.MaxAttempts = 11 },
		func(p *CodexTicketPolicy) { p.FailureCooldownSeconds = 59 }, func(p *CodexTicketPolicy) { p.FailureCooldownSeconds = 86401 },
	} {
		value := base
		modify(&value)
		require.Error(t, value.Validate())
	}
	for _, value := range []CodexTicketPolicy{{60, 0, 1, 60}, {86400, 86399, 10, 86400}} {
		require.NoError(t, value.Validate())
	}
}

func TestCodexTicketPolicyReloadAndReadFailure(t *testing.T) {
	ctx := context.Background()
	repo := &codexTicketSettingRepo{codexPolicyMigrationRepoStub: &codexPolicyMigrationRepoStub{values: map[string]string{}}}
	s := NewSettingService(repo, &config.Config{})
	require.Equal(t, CodexTicketPolicy{3600, 600, 3, 3600}, s.GetOpenAICodexTicketPolicy(ctx))
	custom := CodexTicketPolicy{7200, 0, 5, 1800}
	raw, _ := json.Marshal(custom)
	repo.values[SettingKeyOpenAICodexTicketPolicy] = string(raw)
	s.InvalidateOpenAICodexTicketPolicyCache()
	require.Equal(t, custom, s.GetOpenAICodexTicketPolicy(ctx))
	require.Equal(t, custom, NewSettingService(repo, &config.Config{}).GetOpenAICodexTicketPolicy(ctx))
	repo.err = errors.New("unavailable")
	s.InvalidateOpenAICodexTicketPolicyCache()
	require.Equal(t, custom, s.GetOpenAICodexTicketPolicy(ctx))
	repo.err = nil
	repo.values[SettingKeyOpenAICodexTicketPolicy] = "{}"
	s.InvalidateOpenAICodexTicketPolicyCache()
	require.Equal(t, custom, s.GetOpenAICodexTicketPolicy(ctx))
}

func TestCodexTicketPolicyConcurrentSnapshots(t *testing.T) {
	s := NewSettingService(nil, &config.Config{})
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				s.InvalidateOpenAICodexTicketPolicyCache()
				require.NoError(t, s.GetOpenAICodexTicketPolicy(context.Background()).Validate())
			}
		}()
	}
	wg.Wait()
}
