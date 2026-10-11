package apicompat

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

// Haiku 5.5 只接受 adaptive 思考，但与 Opus/Sonnet 5.5 不同：强制 tool_choice 可用，
// 采样参数原样透传，客户端不给 reasoning.effort 时不替它开启思考。
func TestHaiku55ResponsesThinking(t *testing.T) {
	temperature, topP := 0.7, 0.5
	tests := []struct {
		name           string
		model          string
		effort         string
		toolChoice     string
		temperature    *float64
		topP           *float64
		wantErr        string
		wantThinking   string // 空串表示不下发 thinking
		wantEffort     string
		wantToolChoice string
	}{
		{name: "low", effort: "low", wantThinking: "adaptive", wantEffort: "low"},
		{name: "medium", effort: "medium", wantThinking: "adaptive", wantEffort: "medium"},
		{name: "high", effort: "high", wantThinking: "adaptive", wantEffort: "high"},
		{name: "dotted_alias", model: "anthropic/claude-haiku-5.5", effort: "medium", wantThinking: "adaptive", wantEffort: "medium"},
		{name: "dated_id", model: "claude-haiku-5-5-20261001", effort: "high", wantThinking: "adaptive", wantEffort: "high"},
		{name: "no_reasoning_keeps_upstream_default"},
		{name: "forced_any_with_thinking", effort: "medium", toolChoice: `"required"`, wantThinking: "adaptive", wantEffort: "medium", wantToolChoice: "any"},
		{name: "forced_tool_with_thinking", effort: "high", toolChoice: `{"type":"function","name":"lookup"}`, wantThinking: "adaptive", wantEffort: "high", wantToolChoice: "tool"},
		{name: "forced_any_without_reasoning", toolChoice: `"required"`, wantToolChoice: "any"},
		{name: "sampling_passes_through", effort: "low", temperature: &temperature, topP: &topP, wantThinking: "adaptive", wantEffort: "low"},
		{name: "xhigh_rejected", effort: "xhigh", wantErr: `does not support reasoning effort "xhigh"; use low, medium, high`},
		{name: "max_rejected", effort: "max", wantErr: "does not support reasoning effort"},
		{name: "none_rejected", effort: "none", wantErr: "does not support reasoning effort"},
		{name: "minimal_rejected", effort: "minimal", wantErr: "does not support reasoning effort"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			model := tt.model
			if model == "" {
				model = "claude-haiku-5-5"
			}
			req := &ResponsesRequest{
				Model:       model,
				Input:       json.RawMessage(`"hello"`),
				Temperature: tt.temperature,
				TopP:        tt.topP,
			}
			if tt.effort != "" {
				req.Reasoning = &ResponsesReasoning{Effort: tt.effort}
			}
			if tt.toolChoice != "" {
				req.ToolChoice = json.RawMessage(tt.toolChoice)
			}

			out, err := ResponsesToAnthropicRequest(req)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)

			if tt.wantThinking == "" {
				require.Nil(t, out.Thinking)
				require.Nil(t, out.OutputConfig)
			} else {
				require.NotNil(t, out.Thinking)
				require.Equal(t, tt.wantThinking, out.Thinking.Type)
				require.Zero(t, out.Thinking.BudgetTokens)
				require.NotNil(t, out.OutputConfig)
				require.Equal(t, tt.wantEffort, out.OutputConfig.Effort)
			}
			require.Equal(t, tt.wantToolChoice, gjson.GetBytes(out.ToolChoice, "type").String())
			require.Equal(t, tt.temperature, out.Temperature)
			require.Equal(t, tt.topP, out.TopP)

			// 序列化后的请求体里不能残留手动思考预算。
			raw, err := json.Marshal(out)
			require.NoError(t, err)
			require.False(t, gjson.GetBytes(raw, "thinking.budget_tokens").Exists())
		})
	}
}

// Haiku 4.5 仍走手动思考预算，不受 Haiku 5.5 分支影响。
func TestHaiku45ResponsesThinkingUnchanged(t *testing.T) {
	out, err := ResponsesToAnthropicRequest(&ResponsesRequest{
		Model:     "claude-haiku-4-5",
		Input:     json.RawMessage(`"hello"`),
		Reasoning: &ResponsesReasoning{Effort: "medium"},
	})
	require.NoError(t, err)
	require.Equal(t, "enabled", out.Thinking.Type)
	require.Equal(t, 4096, out.Thinking.BudgetTokens)
}
