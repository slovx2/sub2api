// 工具调用 ID 编码沿用 CPA，见 NOTICE。
package devin

import (
	"encoding/base64"
	"strings"
	"unicode/utf8"
)

const devinToolIDPrefix = "cpa_tid_v1_"

func isPortableToolCallID(id string) bool {
	if id == "" {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' {
			continue
		}
		return false
	}
	return true
}
func EncodeDevinToolCallID(id string) string {
	if id == "" || (isPortableToolCallID(id) && !strings.HasPrefix(id, devinToolIDPrefix)) {
		return id
	}
	return devinToolIDPrefix + base64.RawURLEncoding.EncodeToString([]byte(id))
}
func DecodeDevinToolCallID(id string) string {
	if !strings.HasPrefix(id, devinToolIDPrefix) {
		return id
	}
	decoded, errDecode := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(id, devinToolIDPrefix))
	if errDecode != nil || !utf8.Valid(decoded) || len(decoded) == 0 {
		return id
	}
	original := string(decoded)
	if EncodeDevinToolCallID(original) != id {
		return id
	}
	return original
}
func RestoreDevinToolCallIDs(prompts []DevinPrompt) {
	for i := range prompts {
		for j := range prompts[i].ToolCalls {
			prompts[i].ToolCalls[j].ID = DecodeDevinToolCallID(prompts[i].ToolCalls[j].ID)
		}
		prompts[i].ToolCallID = DecodeDevinToolCallID(prompts[i].ToolCallID)
		prompts[i].OriginalToolCallID = DecodeDevinToolCallID(prompts[i].OriginalToolCallID)
	}
}
