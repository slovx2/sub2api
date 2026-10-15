package devin

import (
	_ "embed"
	"encoding/json"
	"strings"
)

//go:embed models.json
var catalogJSON []byte

type Model struct {
	ID                  string `json:"id"`
	DisplayName         string `json:"display_name"`
	MaxCompletionTokens int    `json:"max_completion_tokens"`
	Thinking            *struct {
		Levels []string `json:"levels"`
	} `json:"thinking"`
}

// 内置目录固定在 NOTICE 中的 CPA 提交；它不表示当前账号拥有所有模型的权限。
var catalog = func() []Model {
	var models []Model
	if err := json.Unmarshal(catalogJSON, &models); err != nil {
		panic(err)
	}
	return models
}()

func LookupModel(id string) *Model {
	for i := range catalog {
		if catalog[i].ID == id {
			return &catalog[i]
		}
	}
	return nil
}

func ModelsJSON() []byte {
	body := make([]byte, 0, len(catalogJSON)+30)
	body = append(body, `{"object":"list","data":`...)
	body = append(body, catalogJSON...)
	return append(body, '}')
}

func ModelIDs() []string {
	ids := make([]string, 0, len(catalog))
	for _, model := range catalog {
		ids = append(ids, model.ID)
	}
	return ids
}

type modelSuffix struct {
	ModelName, RawSuffix string
	HasSuffix            bool
}

// 与 CPA 的模型后缀约定一致：括号/冒号中的强度优先于请求体。
func parseModelSuffix(model string) modelSuffix {
	if i := strings.LastIndex(model, "("); i > 0 && strings.HasSuffix(model, ")") {
		return modelSuffix{model[:i], model[i+1 : len(model)-1], true}
	}
	return modelSuffix{ModelName: model}
}
