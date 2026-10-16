package devin

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// Codex exec_command 的真实描述（含末尾句点与 Windows 追加说明两种形态）。
const codexExecCommandToolDescription = codexExecCommandSentence + "."

func TestRewriteCodexExecCommandDescription(t *testing.T) {
	for name, tc := range map[string]struct {
		description string
		want        string
	}{
		"codex 原话":     {description: codexExecCommandToolDescription, want: devinExecCommandDescription},
		"windows 追加说明": {description: codexExecCommandToolDescription + "\n\nWindows shells...", want: devinExecCommandDescription},
		"自带的等价描述":      {description: devinExecCommandDescription, want: devinExecCommandDescription},
		"只提到 PTY":      {description: "Runs a command in a PTY for the lookup helper.", want: "Runs a command in a PTY for the lookup helper."},
		"调用方自己的工具说明":   {description: "Runs a command in a sandbox and returns its output.", want: "Runs a command in a sandbox and returns its output."},
		"空描述":          {description: "", want: ""},
	} {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, tc.want, rewriteCodexExecCommandDescription(tc.description))
		})
	}
	require.NotContains(t, devinExecCommandDescription, codexExecCommandSentence)
}

func TestNativeRequestReplacesCodexExecCommandDescription(t *testing.T) {
	body, err := json.Marshal(map[string]any{
		"model":    "gpt-6-astra",
		"messages": []any{map[string]any{"role": "user", "content": "run"}},
		"tools": []any{
			map[string]any{"type": "function", "function": map[string]any{
				"name":        "exec_command",
				"description": codexExecCommandToolDescription,
				"parameters":  json.RawMessage(`{"type":"object","properties":{"cmd":{"type":"string"}}}`),
			}},
			map[string]any{"type": "function", "function": map[string]any{
				"name":        "write_stdin",
				"description": "Writes characters to an existing unified exec session and returns recent output.",
				"parameters":  json.RawMessage(`{"type":"object"}`),
			}},
			map[string]any{"type": "function", "function": map[string]any{
				"name":        "lookup",
				"description": "Runs a command in a PTY for the lookup helper.",
				"parameters":  json.RawMessage(`{"type":"object"}`),
			}},
			map[string]any{"type": "function", "function": map[string]any{
				"name":        "exec",
				"description": codexExecCommandToolDescription,
				"parameters":  json.RawMessage(`{"type":"object","properties":{"input":{"type":"string"}}}`),
			}},
		},
	})
	require.NoError(t, err)
	opts := RequestOptions{CustomTools: map[string]json.RawMessage{"exec": json.RawMessage(`{"type":"text"}`)}}
	req, err := NewChatRequest(context.Background(), DevinDefaultBaseURL, "test", "session", body, opts)
	require.NoError(t, err)
	_, payload, err := ReadConnectFrame(req.Body)
	require.NoError(t, err)
	require.NotContains(t, string(payload), codexExecCommandSentence)

	tools := byteFields(t, payload, 10)
	require.Len(t, tools, 4)
	execCommand, writeStdin, lookup, custom := tools[0], tools[1], tools[2], tools[3]

	// 只换描述：工具名、参数 schema 和调用方自己的说明保持原样。
	require.Equal(t, "exec_command", string(byteFields(t, execCommand, 1)[0]))
	require.Equal(t, devinExecCommandDescription, string(byteFields(t, execCommand, 2)[0]))
	require.Contains(t, string(byteFields(t, execCommand, 3)[0]), `"cmd"`)
	require.Equal(t, "Writes characters to an existing unified exec session and returns recent output.", string(byteFields(t, writeStdin, 2)[0]))
	require.Equal(t, "Runs a command in a PTY for the lookup helper.", string(byteFields(t, lookup, 2)[0]))
	require.Equal(t, devinExecCommandDescription, string(byteFields(t, custom, 2)[0]), "custom 工具走同一处替换")
}
