package apicompat

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// Codex responses-lite 把顶层工具包进 functions 命名空间，历史调用不带 namespace。
const codexLiteRequestWithDefaultNamespace = `{
  "model": "gpt-6-astra",
  "input": [
    {"type": "additional_tools", "tools": [
      {"type": "namespace", "name": "functions", "tools": [
        {"type": "custom", "name": "exec", "description": "Run JavaScript", "format": {"type": "grammar", "syntax": "lark", "definition": "start: /[\\s\\S]+/"}},
        {"type": "function", "name": "wait", "description": "Wait", "parameters": {"type": "object", "properties": {}}}
      ]},
      {"type": "namespace", "name": "clock", "tools": [
        {"type": "function", "name": "sleep", "description": "Sleep", "parameters": {"type": "object", "properties": {}}}
      ]}
    ]},
    {"type": "message", "role": "user", "content": "hi"},
    {"type": "custom_tool_call", "call_id": "call_exec", "name": "exec", "input": "await tools.exec_command({cmd: \"ls\"})"},
    {"type": "custom_tool_call_output", "call_id": "call_exec", "output": "ok"},
    {"type": "function_call", "call_id": "call_wait", "name": "wait", "arguments": "{}"},
    {"type": "function_call_output", "call_id": "call_wait", "output": "done"},
    {"type": "function_call", "call_id": "call_wait2", "name": "wait", "namespace": "functions", "arguments": "{}"},
    {"type": "function_call_output", "call_id": "call_wait2", "output": "done"}
  ]
}`

func TestResponsesToChatUnwrapsDefaultFunctionNamespace(t *testing.T) {
	var req ResponsesRequest
	require.NoError(t, json.Unmarshal([]byte(codexLiteRequestWithDefaultNamespace), &req))

	chatReq, err := ResponsesToChatCompletionsRequest(&req)
	require.NoError(t, err)

	var toolNames []string
	for _, tool := range chatReq.Tools {
		require.NotNil(t, tool.Function)
		toolNames = append(toolNames, tool.Function.Name)
	}
	require.Equal(t, []string{"exec", "wait", "clock__sleep"}, toolNames)

	var callNames []string
	for _, message := range chatReq.Messages {
		for _, call := range message.ToolCalls {
			callNames = append(callNames, call.Function.Name)
		}
	}
	require.Equal(t, []string{"exec", "wait", "wait"}, callNames)
}

func TestEffectiveResponsesToolsExposesDefaultNamespaceAsTopLevel(t *testing.T) {
	var req ResponsesRequest
	require.NoError(t, json.Unmarshal([]byte(codexLiteRequestWithDefaultNamespace), &req))

	tools, err := EffectiveResponsesTools(&req)
	require.NoError(t, err)

	require.Equal(t, map[string]bool{"exec": true}, CustomToolNames(tools))
	require.Equal(t, map[string]bool{"wait": true}, FunctionToolNames(tools))
	require.Equal(t, map[string]NamespacedToolName{"clock__sleep": {Namespace: "clock", Name: "sleep"}}, NamespaceToolNames(tools))

	formats := CustomToolFormats(tools)
	require.JSONEq(t, `{"type":"grammar","syntax":"lark","definition":"start: /[\\s\\S]+/"}`, string(formats["exec"]))
}

func TestChatUsageToResponsesUsageAlwaysEmitsCachedTokens(t *testing.T) {
	usage := ChatUsageToResponsesUsage(&ChatUsage{PromptTokens: 3, CompletionTokens: 96, PromptTokensDetails: &ChatTokenDetails{CacheCreationTokens: 146886}})
	encoded, err := json.Marshal(usage)
	require.NoError(t, err)
	require.JSONEq(t, `{"input_tokens":3,"output_tokens":96,"total_tokens":99,"cache_creation_input_tokens":146886,"input_tokens_details":{"cached_tokens":0,"cache_creation_tokens":146886}}`, string(encoded))

	encoded, err = json.Marshal(ChatUsageToResponsesUsage(&ChatUsage{PromptTokens: 5, CompletionTokens: 2}))
	require.NoError(t, err)
	require.JSONEq(t, `{"input_tokens":5,"output_tokens":2,"total_tokens":7,"input_tokens_details":{"cached_tokens":0}}`, string(encoded))
}
