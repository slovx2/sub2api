package service

import "strings"

const (
	// ExcelBPSModelsKey 是账号显式启用的 BPS 模型清单：键缺失=全部模型，空清单=一个都不启用。
	ExcelBPSModelsKey = "openai_excel_bps_models"
	// ExcelBPSModelsMemoryKey 记住上一次的清单，关闭 BPS 后再次打开时自动带回来，
	// 免去每次重新输入模型。
	ExcelBPSModelsMemoryKey = "openai_excel_bps_models_last"
)

// excelBPSModelNames 把 extra 里的模型清单归一化成去空的字符串切片。
func excelBPSModelNames(value any) []string {
	var raw []any
	switch list := value.(type) {
	case []string:
		raw = make([]any, 0, len(list))
		for _, item := range list {
			raw = append(raw, item)
		}
	case []any:
		raw = list
	default:
		return nil
	}
	names := make([]string, 0, len(raw))
	for _, item := range raw {
		name, ok := item.(string)
		if !ok {
			continue
		}
		if trimmed := strings.TrimSpace(name); trimmed != "" {
			names = append(names, trimmed)
		}
	}
	return names
}

// excelBPSModelListIsEmpty 判断清单是否为“显式给出的空清单”（空数组或全空白）。
// 键缺失时返回 false，因为缺失代表“全部模型”而不是空清单。
func excelBPSModelListIsEmpty(value any) bool {
	switch value.(type) {
	case []string, []any:
		return len(excelBPSModelNames(value)) == 0
	default:
		return false
	}
}

// excelBPSModelMemoryRelevant 判断这次改动是否可能影响模型清单记忆。
func excelBPSModelMemoryRelevant(updates map[string]any) bool {
	if updates == nil {
		return false
	}
	if _, exists := updates[ExcelBPSModelsKey]; exists {
		return true
	}
	_, exists := updates["openai_excel_bps"]
	return exists
}

// ApplyExcelBPSModelMemory 在写入前维护模型清单记忆：
//   - 显式给出非空清单：直接使用并刷新记忆；
//   - 明确清空记忆（键为 null）：尊重调用方，不再自动恢复；
//   - 显式空清单：用记忆里的清单恢复（表单重新打开 BPS 时就是这种形态）；
//   - 关闭 BPS：把当前清单记进记忆，供以后重新打开时使用。
//
// 键缺失表示“全部模型”，因此既不清空也不恢复。
func ApplyExcelBPSModelMemory(previous, next map[string]any) {
	if next == nil {
		return
	}
	if value, exists := next[ExcelBPSModelsMemoryKey]; exists && value == nil {
		return
	}
	if names := excelBPSModelNames(next[ExcelBPSModelsKey]); len(names) > 0 {
		next[ExcelBPSModelsMemoryKey] = names
		return
	}
	remembered := excelBPSModelNames(previous[ExcelBPSModelsMemoryKey])
	if len(remembered) == 0 {
		remembered = excelBPSModelNames(previous[ExcelBPSModelsKey])
	}
	if len(remembered) == 0 {
		return
	}
	enabled, hasSwitch := next["openai_excel_bps"].(bool)
	if hasSwitch && !enabled {
		// 关闭 BPS：保留现场，模型清单可以在重新打开时自动带回。
		next[ExcelBPSModelsMemoryKey] = remembered
		return
	}
	wasEnabled, _ := previous["openai_excel_bps"].(bool)
	if hasSwitch || wasEnabled {
		if excelBPSModelListIsEmpty(next[ExcelBPSModelsKey]) {
			next[ExcelBPSModelsKey] = remembered
			next[ExcelBPSModelsMemoryKey] = remembered
		}
	}
}
