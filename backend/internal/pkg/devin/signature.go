package devin

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// CPA 同时回传签名字节和供应商类型；封装后穿过 CC、Responses 和 Messages，
// 避免把 Devin 的签名与其他上游签名混淆，或在格式转换中丢失类型。
func packSignature(signature []byte, kind string) string {
	b, _ := json.Marshal(struct {
		Data []byte `json:"data"`
		Kind string `json:"kind"`
	}{signature, kind})
	return "devin#" + base64.RawURLEncoding.EncodeToString(b)
}

func unpackSignature(s string) ([]byte, string, error) {
	if strings.HasPrefix(s, "sealed.v1.") {
		return []byte(s), "sealed", nil
	}
	for prefix, kind := range map[string]string{"claude#": "anthropic", "gpt#": "openai", "gemini#": "gemini"} {
		if strings.HasPrefix(s, prefix) {
			return []byte(strings.TrimPrefix(s, prefix)), kind, nil
		}
	}
	if strings.HasPrefix(s, "devin#") {
		b, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, "devin#"))
		var value struct {
			Data []byte `json:"data"`
			Kind string `json:"kind"`
		}
		if err != nil || json.Unmarshal(b, &value) != nil || len(value.Data) == 0 {
			return nil, "", fmt.Errorf("invalid Devin reasoning signature")
		}
		return value.Data, value.Kind, nil
	}
	// CPA 可直接接受供应商原始签名。
	if strings.HasPrefix(s, "gAAAA") {
		return []byte(s), "openai", nil
	}
	if strings.HasPrefix(s, "CAQS") || strings.HasPrefix(s, "CAIS") {
		return []byte(s), "anthropic", nil
	}
	return []byte(s), "", nil
}
