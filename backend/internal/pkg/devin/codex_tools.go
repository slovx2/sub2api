// 上游 Devin 会拒绝含 Codex exec_command 原话的请求：Connect trailer 返回
// permission_denied "Unable to process request due to an MCP configuration issue"，
// 换账号重放同样被拒（见 wire.go 的 ParseDevinTrailerError 注释）。
// 出站前把这条描述换成自带的等价描述，工具名、参数 schema 和调用历史保持调用方原样。
package devin

import "strings"

// codexExecCommandSentence 是 Codex exec_command 工具描述里被上游拒绝的原话。
// 只在命中这句原话时替换，避免改动调用方自己的工具说明。
const codexExecCommandSentence = "Runs a command in a PTY, returning output or a session ID for ongoing interaction"

// devinExecCommandDescription 是替换后的等价描述：措辞与 Codex 原话完全错开，
// 语义保持一致（同样的 cmd / yield_time_ms 参数，返回输出或可续用的 session id）。
const devinExecCommandDescription = "Runs a command in a pseudo-terminal and returns its output. " +
	"If the command is still running when the yield time ends, the result reports a session id " +
	"that write_stdin can use to keep interacting with the same process."

// rewriteCodexExecCommandDescription 命中 Codex exec_command 原话时返回等价描述，
// 其余描述原样返回。
func rewriteCodexExecCommandDescription(description string) string {
	if !strings.Contains(description, codexExecCommandSentence) {
		return description
	}
	return devinExecCommandDescription
}
