//go:build unit

package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/devin"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
	"google.golang.org/protobuf/encoding/protowire"
)

func devinTestAccount() *Account {
	a := rawChatCompletionsTestAccount()
	a.Platform = PlatformDevin
	a.Type = AccountTypeOAuth
	a.Credentials = map[string]any{"session_token": "devin-session-token$test", "base_url": "http://upstream.example"}
	return a
}
func devinTestWireResponse() *http.Response {
	text := protowire.AppendString(protowire.AppendTag(nil, 3, protowire.BytesType), "ok")
	var usage []byte
	for _, n := range []struct {
		tag   protowire.Number
		value uint64
	}{{2, 7}, {3, 3}, {4, 2}, {5, 5}, {6, 200}} {
		usage = protowire.AppendVarint(protowire.AppendTag(usage, n.tag, protowire.VarintType), n.value)
	}
	text = protowire.AppendBytes(protowire.AppendTag(text, 7, protowire.BytesType), usage)
	body := append(devin.WrapConnectEnvelope(text), []byte{2, 0, 0, 0, 2, '{', '}'}...)
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/connect+proto"}}, Body: io.NopCloser(bytes.NewReader(body))}
}

func TestDevinGatewayAllEntrypoints(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, path := range []string{"/v1/responses", "/v1/chat/completions", "/v1/messages"} {
		for _, stream := range []bool{false, true} {
			t.Run(path+map[bool]string{true: "/stream", false: "/json"}[stream], func(t *testing.T) {
				payload := map[string]any{"model": "gpt-5.4", "stream": stream, "max_tokens": 256}
				if path == "/v1/responses" {
					payload["input"] = "hello"
				} else {
					payload["messages"] = []any{map[string]string{"role": "user", "content": "hello"}}
				}
				body, err := json.Marshal(payload)
				require.NoError(t, err)
				rec := httptest.NewRecorder()
				c, _ := gin.CreateTestContext(rec)
				c.Request = httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
				up := &httpUpstreamRecorder{resp: devinTestWireResponse()}
				s := &OpenAIGatewayService{cfg: rawChatCompletionsTestConfig(), httpUpstream: up}
				a := devinTestAccount()
				var result *OpenAIForwardResult
				switch path {
				case "/v1/responses":
					result, err = s.Forward(context.Background(), c, a, body)
				case "/v1/chat/completions":
					result, err = s.ForwardAsChatCompletions(context.Background(), c, a, body, "", "")
				case "/v1/messages":
					result, err = s.ForwardAsAnthropic(context.Background(), c, a, body, "", "")
				}
				require.NoError(t, err, rec.Body.String())
				require.NotNil(t, result)
				require.Equal(t, "http://upstream.example"+devin.DevinChatPath, up.lastReq.URL.String())
				require.Equal(t, "application/connect+proto", up.lastReq.Header.Get("Content-Type"))
				require.Equal(t, "Basic devin-session-token$test-devin-session-token$test", up.lastReq.Header.Get("Authorization"))
				require.Equal(t, devin.DevinChatPath, GetActualOpenAIUpstreamEndpoint(c))
				require.Contains(t, rec.Body.String(), "ok")
				require.Equal(t, 12, result.Usage.InputTokens)
				require.Equal(t, 3, result.Usage.OutputTokens)
				require.Equal(t, 5, result.Usage.CacheReadInputTokens)
				require.Equal(t, 2, result.Usage.CacheCreationInputTokens)
				require.Equal(t, stream, result.Stream)
			})
		}
	}
}

func TestDevinLoginPKCEExpiryReplayAndRedaction(t *testing.T) {
	up := &httpUpstreamRecorder{resp: &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"token":"eyJtest"}`))}}
	s := NewDevinOAuthService(nil, up)
	login, err := s.GenerateAuthURL(context.Background(), nil)
	require.NoError(t, err)
	u, err := url.Parse(login["auth_url"])
	require.NoError(t, err)
	require.Equal(t, "app.devin.ai", u.Host)
	require.Equal(t, "S256", u.Query().Get("code_challenge_method"))
	token, err := s.ExchangeCode(context.Background(), login["session_id"], "test-code")
	require.NoError(t, err)
	require.Equal(t, "devin-session-token$eyJtest", token["session_token"])
	require.Equal(t, "https://api.devin.ai/auth/cli/token", up.lastReq.URL.String())
	verifier := gjson.GetBytes(up.lastBody, "code_verifier").String()
	require.GreaterOrEqual(t, len(verifier), 43)
	digest := sha256.Sum256([]byte(verifier))
	require.Equal(t, base64.RawURLEncoding.EncodeToString(digest[:]), u.Query().Get("code_challenge"))
	_, err = s.ExchangeCode(context.Background(), login["session_id"], "test-code")
	require.Error(t, err)
	s.sessions["expired"] = devinLoginSession{created: time.Now().Add(-11 * time.Minute)}
	_, err = s.ExchangeCode(context.Background(), "expired", "test-code")
	require.Error(t, err)
	require.True(t, IsSensitiveCredentialKey("session_token"))
	merged := MergePreservingSensitiveCreds(map[string]any{"session_token": "devin-session-token$old"}, map[string]any{"base_url": "https://server.codeium.com"})
	require.Equal(t, "devin-session-token$old", merged["session_token"])
	require.NoError(t, validateDevinCredentials(AccountTypeOAuth, merged))
	require.Error(t, validateDevinCredentials(AccountTypeAPIKey, merged))
	_, err = buildAccountForCreate(&CreateAccountInput{Platform: PlatformDevin, Type: AccountTypeOAuth, Credentials: map[string]any{}}, map[string]any{})
	require.Error(t, err)
}

func TestDevinSessionIsolationAndCatalog(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("POST", "/v1/responses", nil)
	c.Request.Header.Set("session_id", "client-session")
	a := devinTestAccount()
	id := devinSessionID(c, a, nil)
	require.Equal(t, id, devinSessionID(c, a, []byte(`{"model":"other"}`)))
	a.ID++
	require.NotEqual(t, id, devinSessionID(c, a, nil))
	id = devinSessionID(c, a, nil)
	c.Set("api_key", &APIKey{ID: 99})
	require.NotEqual(t, id, devinSessionID(c, a, nil))
	// 账号模型同步改为实时拉取（见 upstream_models_devin_test.go），不再回落内置目录。
	s := &AccountTestService{}
	_, _, err := s.fetchUpstreamModelList(context.Background(), a)
	var syncErr *UpstreamModelSyncError
	require.ErrorAs(t, err, &syncErr)
	require.Equal(t, UpstreamModelSyncErrorConfiguration, syncErr.Kind)
	require.Equal(t, devin.ModelIDs(), defaultModelsListCandidateIDs(PlatformDevin))
}

func TestDevinRejectsUnsupportedOperationsBeforeUpstream(t *testing.T) {
	a := devinTestAccount()
	require.True(t, a.SupportsOpenAIEndpointCapability(OpenAIEndpointCapabilityChatCompletions))
	for _, capability := range []OpenAIEndpointCapability{OpenAIEndpointCapabilityResponses, OpenAIEndpointCapabilityAlphaSearch, OpenAIEndpointCapabilityEmbeddings, OpenAIEndpointCapabilityLive} {
		require.False(t, a.SupportsOpenAIEndpointCapability(capability))
	}
	for _, input := range []struct{ path, body string }{
		{"/v1/responses/compact", `{"model":"gpt-5.4","input":"hello"}`},
		{"/v1/responses", `{"model":"gpt-5.4","input":"hello","tools":[{"type":"web_search"}]}`},
	} {
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request = httptest.NewRequest("POST", input.path, nil)
		s := &OpenAIGatewayService{}
		_, err := s.Forward(context.Background(), c, a, []byte(input.body))
		require.Error(t, err)
		require.Equal(t, http.StatusBadRequest, rec.Code)
	}
}
