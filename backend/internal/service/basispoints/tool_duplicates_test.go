package basispoints

import (
	"encoding/json"
	"strings"
	"testing"
)

func duplicateExecTool(description string) object {
	return object{
		"type": "custom", "name": "exec", "description": description,
		"format": object{"type": "grammar", "syntax": "lark", "definition": "start: /[\\s\\S]+/"},
	}
}

func execToolNamespace(declaration object) object {
	return object{"type": "namespace", "name": "functions", "tools": []any{declaration}}
}

// 说明：上游这组用例另外覆盖了“继承目录（CatalogCache）”场景；本仓库尚未移植该缓存，
// 因此只保留单请求内的重复声明行为，结论与上游一致：描述/延迟加载差异不算冲突，
// 调用契约变化仍然报错。

func TestDuplicateToolDescriptionsKeepCurrentContract(t *testing.T) {
	source := testSource()
	source["tools"] = []any{execToolNamespace(duplicateExecTool("Current execution instructions"))}
	historical := duplicateExecTool("Older client execution instructions")
	historical["defer_loading"] = true
	source["input"] = []any{
		object{"type": "additional_tools", "tools": []any{execToolNamespace(historical)}},
		message("user", "Continue"),
	}
	raw, _ := json.Marshal(source)
	before := string(raw)
	wire, bridge, err := Prepare(raw, "account/key/thread", nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != before || len(bridge.tools) != 1 {
		t.Fatal("duplicate handling changed the request or retained duplicate tools")
	}
	if got := bridge.tools["functions.exec"]; got.Kind != "custom" || got.Name != "exec" {
		t.Fatal("historical declarations replaced the current tool contract")
	}
	var prepared object
	if err := json.Unmarshal(wire, &prepared); err != nil {
		t.Fatal(err)
	}
	input := mustTestValue[[]any](t, prepared["input"])
	protocol := text(mustTestValue[object](t, mustTestValue[[]any](t, mustTestValue[object](t, input[1])["content"])[0])["text"])
	if strings.Count(protocol, `Client tool "functions.exec"`) != 1 || strings.Contains(protocol, "Older client execution instructions") {
		t.Fatal("upstream catalog did not retain one current declaration")
	}
}

func TestDuplicateFunctionToolsNormalizeSchemaAliases(t *testing.T) {
	schema := object{"type": "object", "properties": object{"cmd": object{"type": "string"}}, "required": []any{"cmd"}, "additionalProperties": false}
	for _, alias := range []string{"parameters", "inputSchema", "input_schema"} {
		t.Run(alias, func(t *testing.T) {
			source := testSource()
			source["tools"] = []any{
				object{"type": "function", "name": "shell", "description": "Current description", "parameters": schema, "strict": true},
				object{"type": "function", "name": "shell", "description": "Previous description", alias: schema, "strict": true},
			}
			_, bridge := mustPrepare(t, source, "scope", nil)
			if len(bridge.tools) != 1 || bridge.tools["shell"].Parameters == nil {
				t.Fatal("function schema or deduplication was lost")
			}
			// 上游还会断言参数类型校验生效；本仓库尚未移植工具参数 schema 校验，
			// 因此这里只验证去重与 schema 归一化。
		})
	}
}

func TestDuplicateToolContractConflictsStillFail(t *testing.T) {
	for _, field := range []string{"type", "format", "strict", "parameters", "encrypted"} {
		t.Run(field, func(t *testing.T) {
			source := testSource()
			source["tools"] = []any{execToolNamespace(duplicateExecTool("Current"))}
			conflicting := duplicateExecTool("Historical")
			switch field {
			case "type":
				conflicting[field] = "function"
			case "format":
				conflicting[field] = object{"type": "text"}
			case "parameters":
				conflicting[field] = object{"type": "object"}
			default:
				conflicting[field] = true
			}
			source["input"] = []any{object{"type": "additional_tools", "tools": []any{execToolNamespace(conflicting)}}, message("user", "Continue")}
			raw, _ := json.Marshal(source)
			if _, _, err := Prepare(raw, "scope", nil); err == nil || !strings.Contains(err.Error(), "conflicting duplicate") {
				t.Fatalf("accepted a changed %s contract: %v", field, err)
			}
		})
	}
}
