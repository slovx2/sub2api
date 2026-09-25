package service

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMergeAccountExtraUpdatePatchesKeysAndDeletesNulls(t *testing.T) {
	base := map[string]any{
		"email":                   "user@example.com",
		"openai_passthrough":      true,
		"openai_excel_bps":        true,
		"openai_excel_bps_models": []any{"gpt-6-astra"},
		"quota_used":              12.5,
	}
	updates := map[string]any{
		"openai_excel_bps_model_aliases": map[string]any{"gpt-6-sol": "gpt-5.6-sol"},
		"openai_excel_bps_models":        []any{"gpt-5.6-sol", "gpt-5.6-luna"},
		"openai_passthrough":             nil,
	}

	merged := mergeAccountExtraUpdate(base, updates)

	require.Equal(t, "user@example.com", merged["email"], "untouched keys must survive")
	require.Equal(t, 12.5, merged["quota_used"], "managed keys must survive")
	require.Equal(t, true, merged["openai_excel_bps"], "keys absent from the patch must survive")
	require.Equal(t, []any{"gpt-5.6-sol", "gpt-5.6-luna"}, merged["openai_excel_bps_models"], "provided keys must be replaced")
	require.Equal(t, map[string]any{"gpt-6-sol": "gpt-5.6-sol"}, merged["openai_excel_bps_model_aliases"])
	_, deleted := merged["openai_passthrough"]
	require.False(t, deleted, "an explicit null deletes the key")

	// The base map must not be mutated in place.
	require.Contains(t, base, "openai_passthrough")
	require.Equal(t, []any{"gpt-6-astra"}, base["openai_excel_bps_models"])
}

func TestMergeAccountExtraUpdateHandlesNilBase(t *testing.T) {
	merged := mergeAccountExtraUpdate(nil, map[string]any{
		"openai_excel_bps":        true,
		"openai_excel_bps_models": nil,
	})
	require.Equal(t, map[string]any{"openai_excel_bps": true}, merged)
}
