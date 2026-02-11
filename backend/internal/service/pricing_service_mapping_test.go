package service

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetModelPricing_ExplicitBillingMappingModels(t *testing.T) {
	svc := &PricingService{
		pricingData: map[string]*LiteLLMModelPricing{
			"claude-opus-4-5":   {InputCostPerToken: 9.9},
			"claude-sonnet-4-5": {InputCostPerToken: 8.8},
		},
	}

	cases := []struct {
		name     string
		model    string
		expected float64
	}{
		{name: "opus 4.6 thinking", model: "claude-opus-4-6-thinking", expected: 9.9},
		{name: "opus 4.6", model: "claude-opus-4-6", expected: 9.9},
		{name: "opus 4.5 thinking", model: "claude-opus-4-5-thinking", expected: 9.9},
		{name: "opus 4.5", model: "claude-opus-4-5", expected: 9.9},
		{name: "sonnet 4.5", model: "claude-sonnet-4-5", expected: 8.8},
		{name: "sonnet 4.5 thinking", model: "claude-sonnet-4-5-thinking", expected: 8.8},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			pricing := svc.GetModelPricing(tc.model)
			require.NotNil(t, pricing)
			require.Equal(t, tc.expected, pricing.InputCostPerToken)
		})
	}
}

func TestGetModelPricing_ExplicitBillingMappingBeatsFuzzy(t *testing.T) {
	svc := &PricingService{
		pricingData: map[string]*LiteLLMModelPricing{
			"claude-opus-4-5":                      {InputCostPerToken: 9.9},
			"openrouter/anthropic/claude-opus-4":   {InputCostPerToken: 1.1},
			"openrouter/anthropic/claude-opus-4.1": {InputCostPerToken: 1.2},
			"vertex_ai/claude-opus-4-5@20251101":   {InputCostPerToken: 1.3},
		},
	}

	pricing := svc.GetModelPricing("claude-opus-4-6-thinking")
	require.NotNil(t, pricing)
	require.Equal(t, 9.9, pricing.InputCostPerToken)
}
