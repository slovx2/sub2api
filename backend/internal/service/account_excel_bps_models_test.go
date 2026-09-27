package service

import (
	"reflect"
	"testing"
)

func TestApplyExcelBPSModelMemory(t *testing.T) {
	previous := map[string]any{
		"openai_excel_bps":      true,
		ExcelBPSModelsKey:       []any{"gpt-6-astra", "gpt-6-sol"},
		"unrelated_runtime_key": true,
	}

	t.Run("关闭 BPS 时记住现场", func(t *testing.T) {
		next := map[string]any{"openai_excel_bps": false}
		ApplyExcelBPSModelMemory(previous, next)
		want := []string{"gpt-6-astra", "gpt-6-sol"}
		if got := excelBPSModelNames(next[ExcelBPSModelsMemoryKey]); !reflect.DeepEqual(got, want) {
			t.Fatalf("memory = %v, want %v", got, want)
		}
		// 关闭时不应把清单塞回 next（保持“未设置”的语义，避免误启用模型）。
		if _, exists := next[ExcelBPSModelsKey]; exists {
			t.Fatalf("disable must not reintroduce models key: %v", next)
		}
	})

	t.Run("重新打开时用记忆恢复空清单", func(t *testing.T) {
		withMemory := map[string]any{"openai_excel_bps": false, ExcelBPSModelsMemoryKey: []any{"gpt-6-astra"}}
		next := map[string]any{"openai_excel_bps": true, ExcelBPSModelsKey: []any{}}
		ApplyExcelBPSModelMemory(withMemory, next)
		if got, want := excelBPSModelNames(next[ExcelBPSModelsKey]), []string{"gpt-6-astra"}; !reflect.DeepEqual(got, want) {
			t.Fatalf("restored models = %v, want %v", got, want)
		}
	})

	t.Run("显式清单优先并刷新记忆", func(t *testing.T) {
		next := map[string]any{"openai_excel_bps": true, ExcelBPSModelsKey: []any{"gpt-6-luna"}}
		ApplyExcelBPSModelMemory(previous, next)
		if got, want := excelBPSModelNames(next[ExcelBPSModelsKey]), []string{"gpt-6-luna"}; !reflect.DeepEqual(got, want) {
			t.Fatalf("models = %v, want %v", got, want)
		}
		if got, want := excelBPSModelNames(next[ExcelBPSModelsMemoryKey]), []string{"gpt-6-luna"}; !reflect.DeepEqual(got, want) {
			t.Fatalf("memory = %v, want %v", got, want)
		}
	})

	t.Run("键缺失代表全部模型，不恢复", func(t *testing.T) {
		next := map[string]any{"openai_excel_bps": true}
		ApplyExcelBPSModelMemory(previous, next)
		if _, exists := next[ExcelBPSModelsKey]; exists {
			t.Fatalf("missing key must stay missing: %v", next)
		}
	})

	t.Run("明确清空记忆时不恢复", func(t *testing.T) {
		next := map[string]any{"openai_excel_bps": true, ExcelBPSModelsKey: []any{}, ExcelBPSModelsMemoryKey: nil}
		ApplyExcelBPSModelMemory(previous, next)
		if got := excelBPSModelNames(next[ExcelBPSModelsKey]); len(got) != 0 {
			t.Fatalf("models = %v, want empty", got)
		}
	})
}
