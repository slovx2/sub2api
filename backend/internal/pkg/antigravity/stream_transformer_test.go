package antigravity

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestStreamingProcessorFinishThinkingOnlyAddsFallback(t *testing.T) {
	processor := NewStreamingProcessor("claude-sonnet-4-5")
	line := buildV1InternalSSELine(t, GeminiResponse{
		Candidates: []GeminiCandidate{
			{
				Content: &GeminiContent{
					Parts: []GeminiPart{
						{Text: "thinking", Thought: true},
					},
				},
			},
		},
		UsageMetadata: &GeminiUsageMetadata{
			PromptTokenCount:     10,
			CandidatesTokenCount: 0,
		},
	})

	_ = processor.ProcessLine(line)
	finishEvents, usage := processor.Finish()

	if usage == nil || usage.OutputTokens != 100 {
		t.Fatalf("output tokens = %v, want 100", usage)
	}

	events := parseSSEDataEvents(t, finishEvents)
	if !hasTextDelta(events) {
		t.Fatalf("expected fallback text delta in finish events")
	}
	if outputTokens, ok := findMessageDeltaOutputTokens(events); !ok || outputTokens != 100 {
		t.Fatalf("message_delta output_tokens = %d (ok=%v), want 100", outputTokens, ok)
	}
}

func TestStreamingProcessorFinishWithContentSkipsFallback(t *testing.T) {
	processor := NewStreamingProcessor("claude-sonnet-4-5")
	line := buildV1InternalSSELine(t, GeminiResponse{
		Candidates: []GeminiCandidate{
			{
				Content: &GeminiContent{
					Parts: []GeminiPart{
						{Text: "thinking", Thought: true},
						{Text: "answer"},
					},
				},
			},
		},
		UsageMetadata: &GeminiUsageMetadata{
			PromptTokenCount:     10,
			CandidatesTokenCount: 12,
		},
	})

	_ = processor.ProcessLine(line)
	finishEvents, usage := processor.Finish()

	if usage == nil || usage.OutputTokens != 12 {
		t.Fatalf("output tokens = %v, want 12", usage)
	}

	events := parseSSEDataEvents(t, finishEvents)
	if hasTextDelta(events) {
		t.Fatalf("unexpected fallback text delta in finish events")
	}
	if outputTokens, ok := findMessageDeltaOutputTokens(events); !ok || outputTokens != 12 {
		t.Fatalf("message_delta output_tokens = %d (ok=%v), want 12", outputTokens, ok)
	}
}

func buildV1InternalSSELine(t *testing.T, resp GeminiResponse) string {
	t.Helper()
	payload, err := json.Marshal(V1InternalResponse{
		Response:   resp,
		ResponseID: "resp-1",
	})
	if err != nil {
		t.Fatalf("marshal v1internal response failed: %v", err)
	}
	return "data: " + string(payload)
}

func parseSSEDataEvents(t *testing.T, raw []byte) []map[string]any {
	t.Helper()
	lines := strings.Split(string(raw), "\n")
	events := make([]map[string]any, 0, 4)
	for _, line := range lines {
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data: "))
		if payload == "" {
			continue
		}
		var event map[string]any
		if err := json.Unmarshal([]byte(payload), &event); err != nil {
			t.Fatalf("unmarshal sse payload failed: %v", err)
		}
		events = append(events, event)
	}
	return events
}

func hasTextDelta(events []map[string]any) bool {
	for _, event := range events {
		if eventType, _ := event["type"].(string); eventType != "content_block_delta" {
			continue
		}
		delta, ok := event["delta"].(map[string]any)
		if !ok {
			continue
		}
		if deltaType, _ := delta["type"].(string); deltaType != "text_delta" {
			continue
		}
		if text, _ := delta["text"].(string); text != "" {
			return true
		}
	}
	return false
}

func findMessageDeltaOutputTokens(events []map[string]any) (int, bool) {
	for _, event := range events {
		if eventType, _ := event["type"].(string); eventType != "message_delta" {
			continue
		}
		usage, ok := event["usage"].(map[string]any)
		if !ok {
			continue
		}
		value, ok := usage["output_tokens"]
		if !ok {
			continue
		}
		switch v := value.(type) {
		case float64:
			return int(v), true
		case int:
			return v, true
		}
	}
	return 0, false
}
