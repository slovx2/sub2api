package service

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// Grok 会把 JSON Schema 声明为 number 的整数参数写成 30000.0。Codex 的 wait、
// write_stdin、exec_command 等工具按整数（u64/i32/usize）反序列化，会以
// "invalid type: floating point" 拒绝整次调用，模型只能反复重试。这里把函数调用
// 参数中小数部分全为 0 的数字改写为整数字面量：数值不变，只改写法。
//
// 只改写完整参数（function_call_arguments.done、output_item.done、终态事件的
// response.output 和非流式响应的 output）；参数增量保持原样，客户端以完整参数为准。
func normalizeGrokFunctionCallArgumentsPayload(account *Account, payload []byte) []byte {
	if account == nil || account.Platform != PlatformGrok || !bytes.Contains(payload, []byte(".0")) || !gjson.ValidBytes(payload) {
		return payload
	}
	root := gjson.ParseBytes(payload)
	out := payload
	normalizeAt := func(path string, arguments gjson.Result) {
		normalized, changed := normalizeIntegralFloatLiterals(arguments.String())
		if !changed {
			return
		}
		if patched, err := sjson.SetBytes(out, path, normalized); err == nil {
			out = patched
		}
	}

	switch root.Get("type").String() {
	case "response.function_call_arguments.done":
		normalizeAt("arguments", root.Get("arguments"))
	case "response.output_item.done":
		if root.Get("item.type").String() == "function_call" {
			normalizeAt("item.arguments", root.Get("item.arguments"))
		}
	}
	for _, prefix := range []string{"response.output", "output"} {
		root.Get(prefix).ForEach(func(index, item gjson.Result) bool {
			if item.Get("type").String() == "function_call" {
				normalizeAt(prefix+"."+index.String()+".arguments", item.Get("arguments"))
			}
			return true
		})
	}
	return out
}

// normalizeIntegralFloatLiterals 在 JSON 文本中把字符串之外的 30000.0、-2.00 等
// 写成整数；带指数或非零小数的数字、字符串内容保持原样。
func normalizeIntegralFloatLiterals(arguments string) (string, bool) {
	if !strings.Contains(arguments, ".0") || !json.Valid([]byte(arguments)) {
		return arguments, false
	}
	var builder strings.Builder
	builder.Grow(len(arguments))
	changed := false
	inString, escaped := false, false
	for i := 0; i < len(arguments); {
		ch := arguments[i]
		if inString {
			builder.WriteByte(ch)
			i++
			switch {
			case escaped:
				escaped = false
			case ch == '\\':
				escaped = true
			case ch == '"':
				inString = false
			}
			continue
		}
		if ch == '"' {
			inString = true
			builder.WriteByte(ch)
			i++
			continue
		}
		if ch == '-' || (ch >= '0' && ch <= '9') {
			end := i
			for end < len(arguments) && strings.IndexByte("+-.0123456789eE", arguments[end]) >= 0 {
				end++
			}
			literal := arguments[i:end]
			if integer, ok := integralFloatLiteral(literal); ok {
				builder.WriteString(integer)
				changed = true
			} else {
				builder.WriteString(literal)
			}
			i = end
			continue
		}
		builder.WriteByte(ch)
		i++
	}
	if !changed {
		return arguments, false
	}
	return builder.String(), true
}

func integralFloatLiteral(literal string) (string, bool) {
	dot := strings.IndexByte(literal, '.')
	if dot <= 0 || strings.ContainsAny(literal, "eE") {
		return "", false
	}
	integer, fraction := literal[:dot], literal[dot+1:]
	if fraction == "" || strings.Trim(fraction, "0") != "" {
		return "", false
	}
	digits := strings.TrimPrefix(integer, "-")
	if digits == "" || strings.Trim(digits, "0123456789") != "" {
		return "", false
	}
	if strings.Trim(digits, "0") == "" {
		return "0", true
	}
	return integer, true
}
