package devin

import (
	"fmt"

	"github.com/tidwall/gjson"
)

// StructuredOutputToolName 与 Devin CLI 的结构化输出工具同名。Devin 对话接口没有
// response_format 字段，CLI 也是声明这个工具并要求模型结束前调用它。
const StructuredOutputToolName = "provide_structured_output"

const structuredOutputInstruction = "When you have the final answer, you MUST call the `" + StructuredOutputToolName +
	"` tool with the complete answer as its arguments instead of replying in plain text. " +
	"The arguments must conform to the tool's JSON schema. If you call it more than once, only the last call counts."

// structuredOutputTool 把 json_schema 响应格式转换为结构化输出工具；text 或缺省时返回 nil。
func structuredOutputTool(format gjson.Result) (*DevinTool, error) {
	switch kind := format.Get("type").String(); kind {
	case "", "text":
		return nil, nil
	case "json_schema":
		schema := format.Get("json_schema.schema").Raw
		if schema == "" || !gjson.Parse(schema).IsObject() {
			return nil, fmt.Errorf("response_format json_schema requires an object schema")
		}
		description := "Provide the final answer as structured output."
		if name := format.Get("json_schema.name").String(); name != "" {
			description += " Output name: " + name + "."
		}
		if extra := format.Get("json_schema.description").String(); extra != "" {
			description += " " + extra
		}
		return &DevinTool{Name: StructuredOutputToolName, Description: description, Parameters: []byte(schema)}, nil
	default:
		return nil, fmt.Errorf("devin does not support response_format=%s", kind)
	}
}
