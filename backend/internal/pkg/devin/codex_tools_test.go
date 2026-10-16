package devin

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// bt 是 Markdown 反引号，单独定义，避免测试源码里出现裸反引号。
const bt = "\x60"

// codexExecCommandToolDescription 是 Codex 工具文档里的原话（含末尾句点）。
var codexExecCommandToolDescription = codexExecCommandSentence + "."

// codeModeExecDescription 复刻 Codex 代码模式里 exec 自定义工具的描述：
// 那句原话只是嵌套工具文档里的一行，其余说明必须保留。
var codeModeExecDescription = "Run JavaScript code to orchestrate/compose tool calls\n" +
	"- All nested tools are available on the global " + bt + "tools" + bt + " object, for example " + bt + "await tools.exec_command(...)" + bt + ".\n\n" +
	"### " + bt + "exec_command" + bt + "\n" + codexExecCommandToolDescription + "\n\n" +
	"exec tool declaration:\n" + bt + bt + bt + "ts\ndeclare const tools: { exec_command(args: { cmd: string }): Promise<unknown>; };\n" + bt + bt + bt + "\n\n" +
	"### " + bt + "apply_patch" + bt + "\nUse the apply_patch tool to edit files.\n\n" +
	"### " + bt + "view_image" + bt + "\nView a local image file.\n"

func TestRewriteCodexExecCommandDescription(t *testing.T) {
	for name, tc := range map[string]struct {
		description string
		want        string
	}{
		"codex 原话":      {description: codexExecCommandToolDescription, want: devinExecCommandSentence + "."},
		"windows 追加说明":  {description: codexExecCommandToolDescription + "\n\nWindows shells...", want: devinExecCommandSentence + ".\n\nWindows shells..."},
		"代码模式的 exec 描述": {description: codeModeExecDescription, want: strings.Replace(codeModeExecDescription, codexExecCommandSentence, devinExecCommandSentence, 1)},
		"自带的等价说明":       {description: devinExecCommandSentence, want: devinExecCommandSentence},
		"只提到 PTY":       {description: "Runs a command in a PTY for the lookup helper.", want: "Runs a command in a PTY for the lookup helper."},
		"调用方自己的工具说明":    {description: "Runs a command in a sandbox and returns its output.", want: "Runs a command in a sandbox and returns its output."},
		"空描述":           {description: "", want: ""},
	} {
		t.Run(name, func(t *testing.T) {
			got := rewriteCodexExecCommandDescription(tc.description)
			require.Equal(t, tc.want, got)
			require.NotContains(t, got, codexExecCommandSentence)
			require.Equal(t, got, rewriteCodexExecCommandDescription(got), "幂等")
		})
	}
	require.NotContains(t, devinExecCommandSentence, codexExecCommandSentence)

	// 代码模式下其余嵌套工具的说明必须保留。
	kept := rewriteCodexExecCommandDescription(codeModeExecDescription)
	require.Contains(t, kept, "### "+bt+"apply_patch"+bt)
	require.Contains(t, kept, "### "+bt+"view_image"+bt)
	require.Contains(t, kept, "All nested tools are available on the global")
}

func TestNativeRequestReplacesCodexExecCommandDescription(t *testing.T) {
	body, err := json.Marshal(map[string]any{
		"model":    "gpt-6-astra",
		"messages": []any{map[string]any{"role": "user", "content": "run"}},
		"tools": []any{
			map[string]any{"type": "function", "function": map[string]any{
				"name":        "exec_command",
				"description": codexExecCommandToolDescription,
				"parameters":  json.RawMessage("{\"type\":\"object\",\"properties\":{\"cmd\":{\"type\":\"string\"}}}"),
			}},
			map[string]any{"type": "function", "function": map[string]any{
				"name":        "write_stdin",
				"description": "Writes characters to an existing unified exec session and returns recent output.",
				"parameters":  json.RawMessage("{\"type\":\"object\"}"),
			}},
			map[string]any{"type": "function", "function": map[string]any{
				"name":        "lookup",
				"description": "Runs a command in a PTY for the lookup helper.",
				"parameters":  json.RawMessage("{\"type\":\"object\"}"),
			}},
			map[string]any{"type": "function", "function": map[string]any{
				"name":        "exec",
				"description": codeModeExecDescription,
				"parameters":  json.RawMessage("{\"type\":\"object\",\"properties\":{\"input\":{\"type\":\"string\"}}}"),
			}},
		},
	})
	require.NoError(t, err)
	opts := RequestOptions{CustomTools: map[string]json.RawMessage{"exec": json.RawMessage("{\"type\":\"text\"}")}}
	req, err := NewChatRequest(context.Background(), DevinDefaultBaseURL, "test", "session", body, opts)
	require.NoError(t, err)
	_, payload, err := ReadConnectFrame(req.Body)
	require.NoError(t, err)
	require.NotContains(t, string(payload), codexExecCommandSentence)

	tools := byteFields(t, payload, 10)
	require.Len(t, tools, 4)
	execCommand, writeStdin, lookup, custom := tools[0], tools[1], tools[2], tools[3]

	// 只换那句话：工具名、参数 schema、调用方自己的说明和其他嵌套工具文档保持原样。
	require.Equal(t, "exec_command", string(byteFields(t, execCommand, 1)[0]))
	require.Equal(t, devinExecCommandSentence+".", string(byteFields(t, execCommand, 2)[0]))
	require.Contains(t, string(byteFields(t, execCommand, 3)[0]), "\"cmd\"")
	require.Equal(t, "Writes characters to an existing unified exec session and returns recent output.", string(byteFields(t, writeStdin, 2)[0]))
	require.Equal(t, "Runs a command in a PTY for the lookup helper.", string(byteFields(t, lookup, 2)[0]))

	customDescription := string(byteFields(t, custom, 2)[0])
	require.Contains(t, customDescription, devinExecCommandSentence)
	require.Contains(t, customDescription, "### "+bt+"apply_patch"+bt)
	require.Contains(t, customDescription, "### "+bt+"view_image"+bt)
	require.Contains(t, customDescription, "await tools.exec_command(...)")
}
