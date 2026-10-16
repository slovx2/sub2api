package service

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/pkg/devin"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protowire"
)

func devinModelConfigEntry(uid, label string) []byte {
	var inner []byte
	inner = protowire.AppendString(protowire.AppendTag(inner, 1, protowire.BytesType), label)
	inner = protowire.AppendVarint(protowire.AppendTag(inner, 5, protowire.VarintType), 1)
	inner = protowire.AppendVarint(protowire.AppendTag(inner, 18, protowire.VarintType), 1000000)
	inner = protowire.AppendString(protowire.AppendTag(inner, 22, protowire.BytesType), uid)
	return protowire.AppendBytes(protowire.AppendTag(nil, 1, protowire.BytesType), inner)
}

func TestSyncUpstreamModelCatalogFetchesLiveDevinModels(t *testing.T) {
	body := bytes.Join([][]byte{
		devinModelConfigEntry("gpt-6-1-sol-low", "GPT-6.1 Sol Low Thinking"),
		devinModelConfigEntry("gpt-6-1-sol-xhigh", "GPT-6.1 Sol XHigh Thinking"),
		devinModelConfigEntry("gpt-6-1-sol-xhigh-priority", "GPT-6.1 Sol XHigh Thinking Fast"),
	}, nil)
	upstream := &httpUpstreamRecorder{resp: &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(body))}}
	repo := &upstreamModelMetadataRepoStub{}
	account := Account{ID: 384, Platform: PlatformDevin, Type: AccountTypeOAuth, Credentials: map[string]any{"session_token": "devin-session-token$test"}}
	syncer := &AccountTestService{accountRepo: repo, httpUpstream: upstream, cfg: upstreamModelSyncTestConfig()}

	catalog, err := syncer.SyncUpstreamModelCatalog(context.Background(), &account)
	require.NoError(t, err)
	require.Empty(t, catalog.Warnings)
	require.Equal(t, []string{"gpt-6-1-sol"}, catalog.Models)
	require.Len(t, upstream.requests, 1)
	require.Equal(t, devin.DevinDefaultBaseURL+devin.DevinCliModelConfigsPath, upstream.requests[0].URL.String())

	// 账号快照落库后，转发时按同步到的档位拼 Devin UID。
	persisted, err := json.Marshal(repo.updates)
	require.NoError(t, err)
	account.Extra = nil
	require.NoError(t, json.Unmarshal(persisted, &account.Extra))
	require.Equal(t, []string{"low", "xhigh"}, devinAccountModelLevels(&account)("gpt-6-1-sol"))
	require.Equal(t, "gpt-6-1-sol-xhigh", devin.ResolveDevinChatModelUID("gpt-6.1-sol", "max", 0, devinAccountModelLevels(&account)))
}
