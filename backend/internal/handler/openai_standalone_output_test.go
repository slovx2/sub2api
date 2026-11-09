package handler

import (
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestValidateFunctionCallOutputRequestNamespacedStandalone(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cases := []struct {
		name     string
		input    string
		accepted bool
	}{
		{"standalone", `{"type":"function_call_output","name":"external_event","namespace":"codex_app","output":"event"}`, true},
		{"standalone_null_id", `{"type":"function_call_output","call_id":null,"name":"external_event","namespace":"codex_app","output":"event"}`, true},
		{"missing_namespace", `{"type":"function_call_output","name":"external_event","output":"event"}`, false},
		{"missing_name", `{"type":"function_call_output","namespace":"codex_app","output":"event"}`, false},
		{"blank_namespace", `{"type":"function_call_output","name":"external_event","namespace":" ","output":"event"}`, false},
		{"invalid_namespace", `{"type":"function_call_output","name":"external_event","namespace":123,"output":"event"}`, false},
		{"empty_call_id_is_not_standalone", `{"type":"function_call_output","call_id":"","name":"external_event","namespace":"codex_app","output":"event"}`, false},
		{"orphan_call_id", `{"type":"function_call_output","call_id":"call_orphan","name":"external_event","namespace":"codex_app","output":"event"}`, false},
		{"other_output_type", `{"type":"function_call_output","output":"missing"},{"type":"custom_tool_call_output","name":"external_event","namespace":"codex_app","output":"event"}`, false},
		{"standalone_does_not_exempt_orphan", `{"type":"function_call_output","name":"external_event","namespace":"codex_app","output":"event"},{"type":"function_call_output","call_id":"call_orphan","output":"orphan"}`, false},
		{"paired_output", `{"type":"function_call","call_id":"call_real","name":"lookup","arguments":"{}"},{"type":"function_call_output","call_id":"call_real","output":"result"}`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			h := &OpenAIGatewayHandler{}
			body := []byte(`{"model":"gpt-6.1-sol","input":[` + tc.input + `]}`)
			require.Equal(t, tc.accepted, h.validateFunctionCallOutputRequest(c, body, zap.NewNop()))
			if !tc.accepted {
				require.Equal(t, 400, w.Code)
			}
		})
	}
}
