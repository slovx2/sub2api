package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestParseLiveCallRequestOfficialJSONPreservesSession(t *testing.T) {
	gin.SetMode(gin.TestMode)
	session := `{"model":"gpt-live-test","delegation":{"type":"client"},"instructions":"hello"}`
	body := `{"session":` + session + `,"transport":{"type":"webrtc","sdp":"v=0\r\n"}}`
	request := httptest.NewRequest("POST", "/v1/live/sessions", bytes.NewBufferString(body))
	request.Header.Set("Content-Type", "application/json")
	context, _ := gin.CreateTestContext(httptest.NewRecorder())
	context.Request = request

	parsed, err := parseLiveCallRequest(context)
	require.NoError(t, err)
	require.Equal(t, "v=0\r\n", parsed.SDP)
	require.JSONEq(t, session, string(parsed.Session))
	require.Equal(t, "client", jsonPathString(t, parsed.Session, "delegation", "type"))
}

func TestParseLiveCallRequestRejectsLegacyAndInvalidShapes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	testCases := []struct {
		body string
		want string
	}{
		{`{"session":{"model":"gpt-live-test"},"sdp":"v=0"}`, "transport.sdp is required"},
		{`{"session":{"model":"gpt-live-test"},"transport":{"type":"websocket","sdp":"v=0"}}`, "transport.type must be webrtc"},
		{`{"session":{"model":"gpt-live-test"},"transport":{"type":"webrtc"}}`, "transport.sdp is required"},
		{`{"session":[],"transport":{"type":"webrtc","sdp":"v=0"}}`, "session must be a JSON object"},
		{`{"session":null,"transport":{"type":"webrtc","sdp":"v=0"}}`, "session must be a JSON object"},
		{`{"session":{"model":"gpt-live-test"},"transport":{"type":"webrtc","sdp":"v=0"}} {}`, "request body must contain one JSON object"},
	}
	for _, tc := range testCases {
		request := httptest.NewRequest("POST", "/v1/live/sessions", bytes.NewBufferString(tc.body))
		request.Header.Set("Content-Type", "application/json")
		context, _ := gin.CreateTestContext(httptest.NewRecorder())
		context.Request = request
		_, err := parseLiveCallRequest(context)
		require.Error(t, err, tc.body)
		require.Contains(t, err.Error(), tc.want, tc.body)
	}
}

func TestWriteLiveCreateResponseUsesOfficialEnvelope(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(recorder)
	writeLiveCreateResponse(context, &service.LiveCallCreated{
		CallID: "call_123",
		SDP:    []byte("v=answer"),
	})
	require.Equal(t, http.StatusCreated, recorder.Code)
	require.JSONEq(t, `{
		"session":{"id":"call_123"},
		"transport":{"type":"webrtc","sdp":"v=answer"}
	}`, recorder.Body.String())
}

func TestLiveEnabledForAPIKey(t *testing.T) {
	require.False(t, liveEnabledForAPIKey(nil))
	require.False(t, liveEnabledForAPIKey(&service.APIKey{}))
	require.False(t, liveEnabledForAPIKey(&service.APIKey{
		Group: &service.Group{Platform: service.PlatformOpenAI},
	}))
	require.False(t, liveEnabledForAPIKey(&service.APIKey{
		Group: &service.Group{Platform: service.PlatformAnthropic, AllowLive: true},
	}))
	require.True(t, liveEnabledForAPIKey(&service.APIKey{
		Group: &service.Group{Platform: service.PlatformOpenAI, AllowLive: true},
	}))
	require.True(t, liveEnabledForAPIKey(&service.APIKey{
		Group: &service.Group{Platform: service.PlatformComposite, AllowLive: true},
	}))
}

func jsonPathString(t *testing.T, raw json.RawMessage, keys ...string) string {
	t.Helper()
	var value any
	require.NoError(t, json.Unmarshal(raw, &value))
	current := value
	for _, key := range keys {
		object, ok := current.(map[string]any)
		require.True(t, ok)
		current = object[key]
	}
	result, ok := current.(string)
	require.True(t, ok)
	return result
}
