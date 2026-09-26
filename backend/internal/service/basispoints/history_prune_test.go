package basispoints

import (
	"encoding/json"
	"testing"
)

func pruneItem(t *testing.T, raw string) object {
	t.Helper()
	var item object
	if err := json.Unmarshal([]byte(raw), &item); err != nil {
		t.Fatalf("invalid fixture %q: %v", raw, err)
	}
	return item
}

// 最后一个压缩项之前、且不属于压缩链的条目已被上游取代，转发时必须丢弃，
// 否则长会话每次请求都要把整段历史重新上传一遍。
func TestTranslateHistoryDropsSupersededItems(t *testing.T) {
	bridge := &Bridge{tools: map[string]tool{}, unsupportedTools: map[string]bool{}}
	input := []any{
		pruneItem(t, `{"type":"message","role":"user","content":[{"type":"input_text","text":"before"}]}`),
		pruneItem(t, `{"type":"compaction","id":"cmp_a","encrypted_content":"a"}`),
		pruneItem(t, `{"type":"message","role":"user","content":[{"type":"input_text","text":"middle"}]}`),
		pruneItem(t, `{"type":"compaction","id":"cmp_b","encrypted_content":"b"}`),
		pruneItem(t, `{"type":"message","role":"user","content":[{"type":"input_text","text":"after"}]}`),
	}
	result, err := bridge.translateHistory(input)
	if err != nil {
		t.Fatalf("translateHistory: %v", err)
	}
	if len(result) != 3 {
		t.Fatalf("expected 3 items, got %d: %v", len(result), result)
	}
	for index, want := range []string{"cmp_a", "cmp_b", ""} {
		item, _ := result[index].(object)
		if want != "" && text(item["id"]) != want {
			t.Fatalf("item %d: want compaction %s, got %v", index, want, item)
		}
	}
	last, _ := result[2].(object)
	if text(last["type"]) != "message" {
		t.Fatalf("expected the trailing message to survive, got %v", last)
	}
}

// 没有压缩项时不裁剪任何内容。
func TestTranslateHistoryKeepsHistoryWithoutCompaction(t *testing.T) {
	bridge := &Bridge{tools: map[string]tool{}, unsupportedTools: map[string]bool{}}
	input := []any{
		pruneItem(t, `{"type":"message","role":"user","content":[{"type":"input_text","text":"one"}]}`),
		pruneItem(t, `{"type":"message","role":"assistant","content":[{"type":"output_text","text":"two"}]}`),
	}
	result, err := bridge.translateHistory(input)
	if err != nil {
		t.Fatalf("translateHistory: %v", err)
	}
	if len(result) != 2 {
		t.Fatalf("expected 2 items, got %d", len(result))
	}
}
