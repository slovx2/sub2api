package service

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/pkg/claude"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

const anthropicClientEntrypointKey = "anthropic_client_entrypoint"

// AnthropicClientEntrypoint 返回显式入口覆写；缺省或非法值保持原转发行为。
// 仅 Anthropic 直连账号使用，Vertex/Bedrock 等其他协议不参与。
func (a *Account) AnthropicClientEntrypoint() string {
	if a == nil || a.Platform != PlatformAnthropic ||
		(a.Type != AccountTypeOAuth && a.Type != AccountTypeSetupToken && a.Type != AccountTypeAPIKey) {
		return ""
	}
	value, _ := a.Extra[anthropicClientEntrypointKey].(string)
	if value == "cli" || value == "sdk-ts" {
		return value
	}
	return ""
}

var billingEntrypointPattern = regexp.MustCompile(`\bcc_entrypoint=[^;\s]*`)
var userAgentEntrypointPattern = regexp.MustCompile(`(claude-cli/[^\s]+\s+\([^,()]+,\s*)[^,()]+`)

// rewriteAnthropicEntrypointBody 只修改现有计费文本块，不创建 system 或计费块。
func rewriteAnthropicEntrypointBody(body []byte, account *Account) []byte {
	entrypoint := account.AnthropicClientEntrypoint()
	if entrypoint == "" {
		return body
	}
	system := gjson.GetBytes(body, "system")
	if !system.IsArray() {
		return body
	}
	for i, block := range system.Array() {
		value := block.Get("text")
		if block.Get("type").String() != "text" || value.Type != gjson.String ||
			!strings.HasPrefix(value.String(), "x-anthropic-billing-header:") {
			continue
		}
		text := value.String()
		if billingEntrypointPattern.MatchString(text) {
			text = billingEntrypointPattern.ReplaceAllString(text, "cc_entrypoint="+entrypoint)
		} else {
			text = strings.TrimRight(text, " ;") + "; cc_entrypoint=" + entrypoint + ";"
		}
		if updated, err := sjson.SetBytes(body, fmt.Sprintf("system.%d.text", i), text); err == nil {
			body = updated
		}
	}
	return body
}

// applyAnthropicEntrypointHeader 在指纹、mimic 和账号请求头覆写后执行，避免入口被覆盖。
// 保留 Claude UA 的版本和额外 SDK 信息；没有 Claude UA 时使用现有默认 UA。
func applyAnthropicEntrypointHeader(header http.Header, account *Account) {
	entrypoint := account.AnthropicClientEntrypoint()
	if entrypoint == "" {
		return
	}
	ua := getHeaderRaw(header, "User-Agent")
	if !userAgentEntrypointPattern.MatchString(ua) {
		if strings.HasPrefix(ua, "claude-cli/") && !strings.Contains(ua, "(") {
			ua += " (external, " + entrypoint + ")"
		} else {
			ua = userAgentEntrypointPattern.ReplaceAllString(claude.DefaultUserAgent(), "${1}"+entrypoint)
		}
	} else {
		ua = userAgentEntrypointPattern.ReplaceAllString(ua, "${1}"+entrypoint)
	}
	setHeaderRaw(header, "User-Agent", ua)
}
