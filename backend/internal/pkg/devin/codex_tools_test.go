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

// Codex exec_command 工具文档里的原话（含末尾句点）。
var codexExecCommandToolDescription = codexToolSentences[0].original + "."

// Codex write_stdin 工具文档里的原话。
var codexWriteStdinToolDescription = codexToolSentences[1].original

// codeModeExecDescription 复刻 Codex 代码模式里 exec 自定义工具的描述：
// 两句原话只是嵌套工具文档里的两行，其余说明必须保留。
var codeModeExecDescription = "Run JavaScript code to orchestrate/compose tool calls\n" +
	"- All nested tools are available on the global " + bt + "tools" + bt + " object, for example " + bt + "await tools.exec_command(...)" + bt + ".\n\n" +
	"### " + bt + "exec_command" + bt + "\n" + codexExecCommandToolDescription + "\n\n" +
	"exec tool declaration:\n" + bt + bt + bt + "ts\ndeclare const tools: { exec_command(args: { cmd: string }): Promise<unknown>; };\n" + bt + bt + bt + "\n\n" +
	"### " + bt + "write_stdin" + bt + "\n" + codexWriteStdinToolDescription + "\n\n" +
	"### " + bt + "apply_patch" + bt + "\nUse the apply_patch tool to edit files.\n\n" +
	"### " + bt + "view_image" + bt + "\nView a local image file.\n"

func rewriteAll(description string) string {
	for _, sentence := range codexToolSentences {
		description = strings.ReplaceAll(description, sentence.original, sentence.replacement)
	}
	return description
}

func TestRewriteCodexToolDescription(t *testing.T) {
	for name, tc := range map[string]struct {
		description string
		want        string
	}{
		"exec_command 原话": {description: codexExecCommandToolDescription, want: codexToolSentences[0].replacement + "."},
		"write_stdin 原话":  {description: codexWriteStdinToolDescription, want: codexToolSentences[1].replacement},
		"windows 追加说明":    {description: codexExecCommandToolDescription + "\n\nWindows shells...", want: codexToolSentences[0].replacement + ".\n\nWindows shells..."},
		"代码模式的 exec 描述":   {description: codeModeExecDescription, want: rewriteAll(codeModeExecDescription)},
		"自带的等价说明":         {description: codexToolSentences[0].replacement, want: codexToolSentences[0].replacement},
		"只提到 PTY":         {description: "Runs a command in a PTY for the lookup helper.", want: "Runs a command in a PTY for the lookup helper."},
		"调用方自己的工具说明":      {description: "Runs a command in a sandbox and returns its output.", want: "Runs a command in a sandbox and returns its output."},
		"空描述":             {description: "", want: ""},
	} {
		t.Run(name, func(t *testing.T) {
			got := rewriteCodexToolDescription(tc.description)
			require.Equal(t, tc.want, got)
			for _, sentence := range codexToolSentences {
				require.NotContains(t, got, sentence.original)
				require.NotContains(t, sentence.replacement, sentence.original)
			}
			require.Equal(t, got, rewriteCodexToolDescription(got), "幂等")
		})
	}

	// 代码模式下其余嵌套工具的说明必须保留。
	kept := rewriteCodexToolDescription(codeModeExecDescription)
	require.Contains(t, kept, "### "+bt+"apply_patch"+bt)
	require.Contains(t, kept, "### "+bt+"view_image"+bt)
	require.Contains(t, kept, "All nested tools are available on the global")
}

func TestNativeRequestReplacesCodexToolDescriptions(t *testing.T) {
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
				"description": codexWriteStdinToolDescription,
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
	for _, sentence := range codexToolSentences {
		require.NotContains(t, string(payload), sentence.original)
	}

	tools := byteFields(t, payload, 10)
	require.Len(t, tools, 4)
	execCommand, writeStdin, lookup, custom := tools[0], tools[1], tools[2], tools[3]

	// 只换那几句话：工具名、参数 schema、调用方自己的说明和其他嵌套工具文档保持原样。
	require.Equal(t, "exec_command", string(byteFields(t, execCommand, 1)[0]))
	require.Equal(t, codexToolSentences[0].replacement+".", string(byteFields(t, execCommand, 2)[0]))
	require.Contains(t, string(byteFields(t, execCommand, 3)[0]), "\"cmd\"")
	require.Equal(t, codexToolSentences[1].replacement, string(byteFields(t, writeStdin, 2)[0]))
	require.Equal(t, "Runs a command in a PTY for the lookup helper.", string(byteFields(t, lookup, 2)[0]))

	customDescription := string(byteFields(t, custom, 2)[0])
	require.Contains(t, customDescription, codexToolSentences[0].replacement)
	require.Contains(t, customDescription, codexToolSentences[1].replacement)
	require.Contains(t, customDescription, "### "+bt+"apply_patch"+bt)
	require.Contains(t, customDescription, "### "+bt+"view_image"+bt)
	require.Contains(t, customDescription, "await tools.exec_command(...)")
}
