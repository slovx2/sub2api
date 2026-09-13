package handler

import (
	"bytes"
	"encoding/json"
	"errors"
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

func TestWriteLiveCreateErrorPassesThroughUpstreamBody(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler := &OpenAIGatewayHandler{}

	t.Run("400 preserves type code param and message", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		context, _ := gin.CreateTestContext(recorder)
		handler.writeLiveCreateError(context, &service.UpstreamFailoverError{
			StatusCode:   http.StatusBadRequest,
			ResponseBody: []byte(`{"error":{"type":"invalid_request_error","code":"invalid_value","param":"session.input","message":"input messages must alternate"}}`),
		})
		require.Equal(t, http.StatusBadRequest, recorder.Code)
		require.JSONEq(t, `{
			"error":{
				"type":"invalid_request_error",
				"code":"invalid_value",
				"param":"session.input",
				"message":"input messages must alternate"
			}
		}`, recorder.Body.String())
	})

	t.Run("500 preserves upstream message", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		context, _ := gin.CreateTestContext(recorder)
		handler.writeLiveCreateError(context, &service.UpstreamFailoverError{
			StatusCode:   http.StatusInternalServerError,
			ResponseBody: []byte(`{"error":{"type":"server_error","message":"live create failed internally"}}`),
		})
		require.Equal(t, http.StatusInternalServerError, recorder.Code)
		require.JSONEq(t, `{
			"error":{
				"type":"server_error",
				"message":"live create failed internally"
			}
		}`, recorder.Body.String())
	})

	t.Run("401 does not expose upstream credential body", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		context, _ := gin.CreateTestContext(recorder)
		handler.writeLiveCreateError(context, &service.UpstreamFailoverError{
			StatusCode:   http.StatusUnauthorized,
			ResponseBody: []byte(`{"error":{"message":"Invalid bearer token","refresh_token":"must-not-leak"}}`),
		})
		require.Equal(t, http.StatusBadGateway, recorder.Code)
		require.Contains(t, recorder.Body.String(), "Upstream authentication failed")
		require.NotContains(t, recorder.Body.String(), "must-not-leak")
		require.NotContains(t, recorder.Body.String(), "Invalid bearer token")
	})
}

func TestWriteLiveCreateErrorKeepsGatewayFailures(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler := &OpenAIGatewayHandler{}

	recorder := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(recorder)
	handler.writeLiveCreateError(context, service.ErrLiveUnavailable)
	require.Equal(t, http.StatusServiceUnavailable, recorder.Code)
	require.Contains(t, recorder.Body.String(), "Live is unavailable")

	recorder = httptest.NewRecorder()
	context, _ = gin.CreateTestContext(recorder)
	handler.writeLiveCreateError(context, errors.New("dial timeout"))
	require.Equal(t, http.StatusBadGateway, recorder.Code)
	require.JSONEq(t, `{"error":{"type":"api_error","message":"Live upstream request failed"}}`, recorder.Body.String())
}
