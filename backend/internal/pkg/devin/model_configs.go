package devin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"google.golang.org/protobuf/encoding/protowire"
)

// DevinCliModelConfigsPath 是 Devin CLI 拉取账号可用模型的 Connect-RPC unary 端点，只读、不消耗推理额度。
// 字段编号与 UID 聚合规则移植自 CPA cmd/fetch_devin_models，见 NOTICE。
const DevinCliModelConfigsPath = "/exa.api_server_pb.ApiServerService/GetCliModelConfigs"

// LiveModel 是按基础模型聚合后的账号模型；Levels 为该账号实际可用的思考档位。
type LiveModel struct {
	ID            string
	DisplayName   string
	ContextLength int
	Multimodal    bool
	Levels        []string
}

type rawModelConfig struct {
	UID, Label    string
	ContextLength int
	Multimodal    bool
}

// NewCliModelConfigsRequest 构建账号模型配置请求。
func NewCliModelConfigsRequest(ctx context.Context, baseURL, token string) (*http.Request, error) {
	var body []byte
	body = protowire.AppendTag(body, 1, protowire.BytesType)
	body = protowire.AppendBytes(body, BuildDevinClientMetadataBytes(token, "", ""))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(baseURL, "/")+DevinCliModelConfigsPath, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Basic "+token+"-"+token)
	req.Header.Set("Content-Type", "application/proto")
	req.Header.Set("Connect-Protocol-Version", "1")
	req.Header.Set("User-Agent", "connect-go/1.19.1 (go1.25.0)")
	return req, nil
}

// ParseCliModelConfigs 解析响应并把带档位后缀的 UID 聚合为基础模型，保持上游顺序。
func ParseCliModelConfigs(data []byte) ([]LiveModel, error) {
	var raws []rawModelConfig
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			return nil, errors.New("malformed Devin model config tag")
		}
		data = data[n:]
		if num == 1 && typ == protowire.BytesType {
			sub, m := protowire.ConsumeBytes(data)
			if m < 0 {
				return nil, errors.New("malformed Devin model config")
			}
			data = data[m:]
			if raw := parseRawModelConfig(sub); raw.UID != "" {
				raws = append(raws, raw)
			}
			continue
		}
		skip := protowire.ConsumeFieldValue(num, typ, data)
		if skip < 0 {
			return nil, errors.New("malformed Devin model config field")
		}
		data = data[skip:]
	}
	return aggregateModelConfigs(raws), nil
}

func parseRawModelConfig(b []byte) rawModelConfig {
	var m rawModelConfig
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			break
		}
		b = b[n:]
		switch {
		case num == 1 && typ == protowire.BytesType:
			if v, l := protowire.ConsumeString(b); l >= 0 {
				m.Label, b = v, b[l:]
				continue
			}
		case num == 5 && typ == protowire.VarintType:
			if v, l := protowire.ConsumeVarint(b); l >= 0 {
				m.Multimodal, b = v == 1, b[l:]
				continue
			}
		case num == 18 && typ == protowire.VarintType:
			if v, l := protowire.ConsumeVarint(b); l >= 0 {
				m.ContextLength, b = int(v), b[l:]
				continue
			}
		case num == 22 && typ == protowire.BytesType:
			if v, l := protowire.ConsumeString(b); l >= 0 {
				m.UID, b = v, b[l:]
				continue
			}
		}
		skip := protowire.ConsumeFieldValue(num, typ, b)
		if skip < 0 {
			break
		}
		b = b[skip:]
	}
	return m
}

func aggregateModelConfigs(raws []rawModelConfig) []LiveModel {
	grouped := make(map[string]*LiveModel)
	levels := make(map[string]map[string]bool)
	var order []string
	for _, raw := range raws {
		base, level := splitDevinUID(raw.UID)
		entry, exists := grouped[base]
		if !exists {
			entry = &LiveModel{ID: base, DisplayName: cleanDevinDisplayName(raw.Label)}
			grouped[base] = entry
			levels[base] = make(map[string]bool)
			order = append(order, base)
		}
		if base == raw.UID {
			entry.DisplayName = cleanDevinDisplayName(raw.Label)
		}
		entry.Multimodal = entry.Multimodal || raw.Multimodal
		entry.ContextLength = max(entry.ContextLength, raw.ContextLength)
		if level != "" {
			levels[base][level] = true
		}
	}
	out := make([]LiveModel, 0, len(order))
	for _, id := range order {
		entry := grouped[id]
		for _, level := range devinLevelOrder {
			if levels[id][level] {
				entry.Levels = append(entry.Levels, level)
			}
		}
		out = append(out, *entry)
	}
	return out
}

// LiveModelsCatalogJSON 输出上游模型目录（OpenAI 列表形状），带账号同步所需的能力字段：
// 思考档位、输入模态与上下文窗口，供账号快照保存并用于解析 Devin 模型 UID。
func LiveModelsCatalogJSON(models []LiveModel) ([]byte, error) {
	data := make([]map[string]any, 0, len(models))
	for _, model := range models {
		modalities := []string{"text"}
		if model.Multimodal {
			modalities = append(modalities, "image")
		}
		reasoning := len(model.Levels) > 1 || (len(model.Levels) == 1 && model.Levels[0] != "none")
		entry := map[string]any{
			"id": model.ID, "object": "model", "owned_by": "devin", "display_name": model.DisplayName,
			"input_modalities": modalities, "reasoning": reasoning, "max_output_tokens": 64000,
		}
		if model.ContextLength > 0 {
			entry["context_window"] = model.ContextLength
		}
		if len(model.Levels) > 0 {
			entry["supported_reasoning_levels"] = model.Levels
		}
		data = append(data, entry)
	}
	return json.Marshal(map[string]any{"object": "list", "data": data})
}
