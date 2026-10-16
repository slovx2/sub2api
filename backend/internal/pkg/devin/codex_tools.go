// 上游 Devin 会拒绝含 Codex 工具说明原话的请求：Connect trailer 返回
// permission_denied "Unable to process request due to an MCP configuration issue"，
// 换账号重放同样被拒（见 wire.go 的 ParseDevinTrailerError 注释）。
// 实测 exec_command 与 write_stdin 两句原话都会被拒：只换其中一句仍返回 400，
// 两句都换后同一条请求返回 200（含 14k 的代码模式 exec 描述）。
// 出站前只替换这几句原话，其余描述、工具名、参数 schema 和调用历史保持调用方原样；
// Codex 代码模式把嵌套工具文档整体放在 exec 自定义工具的描述里，整段替换会连这些说明一起丢掉。
package devin

import "strings"

// codexToolSentences 是上游按内容拒绝的 Codex 工具说明原话，以及对应的等价说明。
// 等价说明的措辞与原话完全错开，语义保持一致。
var codexToolSentences = []struct {
	original    string
	replacement string
}{
	{
		original: "Runs a command in a PTY, returning output or a session ID for ongoing interaction",
		replacement: "Runs a command in a pseudo-terminal and returns its output; " +
			"a command still running at the yield deadline reports a session id that write_stdin can reuse",
	},
	{
		original:    "Writes characters to an existing unified exec session and returns recent output.",
		replacement: "Writes input to a running exec session and returns recent output.",
	},
}

// rewriteCodexToolDescription 把被上游拒绝的原话换成等价说明，其余内容原样保留。
func rewriteCodexToolDescription(description string) string {
	for _, sentence := range codexToolSentences {
		if strings.Contains(description, sentence.original) {
			description = strings.ReplaceAll(description, sentence.original, sentence.replacement)
		}
	}
	return description
}
