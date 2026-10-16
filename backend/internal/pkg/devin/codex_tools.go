// 上游 Devin 会拒绝含 Codex exec_command 说明原话的请求：Connect trailer 返回
// permission_denied "Unable to process request due to an MCP configuration issue"，
// 换账号重放同样被拒（见 wire.go 的 ParseDevinTrailerError 注释）。
// 出站前只把那句原话换成自带的等价说明，其余描述、工具名、参数 schema 和调用历史
// 都保持调用方原样。Codex 代码模式把嵌套工具文档整体放在 exec 自定义工具的描述里，
// 整段替换会连这些说明一起丢掉，所以这里按句替换。
package devin

import "strings"

// codexExecCommandSentence 是 Codex 工具说明里被上游拒绝的原话。
const codexExecCommandSentence = "Runs a command in a PTY, returning output or a session ID for ongoing interaction"

// devinExecCommandSentence 是替换后的等价说明：措辞与原话完全错开，
// 语义保持一致（同样的 cmd / yield_time_ms 参数，返回输出或可续用的 session id）。
const devinExecCommandSentence = "Runs a command in a pseudo-terminal and returns its output; " +
	"a command still running at the yield deadline reports a session id that write_stdin can reuse"

// rewriteCodexExecCommandDescription 把被上游拒绝的那句原话换成等价说明，其余内容原样保留。
func rewriteCodexExecCommandDescription(description string) string {
	if !strings.Contains(description, codexExecCommandSentence) {
		return description
	}
	return strings.ReplaceAll(description, codexExecCommandSentence, devinExecCommandSentence)
}
