package basispoints

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// HTTPS image references pass through; this bridge never uploads client image data.
// StripInputImages removes image parts from expanded message/tool history before
// validation or attachment handling. Do not traverse tool arguments, schemas or
// text: image-shaped application data there is not a Responses image input.
func StripInputImages(raw []byte) ([]byte, error) {
	var source object
	if err := decode(raw, &source); err != nil || source == nil {
		return nil, fmt.Errorf("invalid Basispoints request JSON")
	}
	input, _ := source["input"].([]any)
	changed := false
	for _, rawItem := range input {
		item, _ := rawItem.(object)
		field := "content"
		switch text(item["type"]) {
		case "", "message":
		case "function_call_output", "custom_tool_call_output":
			field = "output"
		default:
			continue
		}
		parts, ok := item[field].([]any)
		if !ok {
			continue
		}
		kept := make([]any, 0, len(parts))
		for _, rawPart := range parts {
			part, _ := rawPart.(object)
			if text(part["type"]) != "input_image" {
				kept = append(kept, rawPart)
			}
		}
		if len(kept) == len(parts) {
			continue
		}
		// Preserve image-only messages and tool results with a truthful marker.
		// Empty content can be rejected upstream; dropping a tool result breaks
		// its call_id pairing and prevents the conversation from continuing.
		if len(kept) == 0 {
			kept = append(kept, object{"type": "input_text", "text": "[Image omitted because Excel / BPS image support is disabled.]"})
		}
		item[field] = kept
		changed = true
	}
	if !changed {
		return raw, nil
	}
	return json.Marshal(source)
}
func validateImage(part object) error {
	raw, ok := part["image_url"].(string)
	if !ok || raw == "" {
		return fmt.Errorf("basispoints input_image requires an HTTPS image_url; file IDs are unsupported")
	}
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(raw)), "data:") {
		return fmt.Errorf("basispoints does not accept data:image/base64 image input; provide an HTTPS image URL, or disable Basispoints and start a new conversation to send this image")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.Opaque != "" || strings.TrimSpace(raw) != raw {
		return fmt.Errorf("basispoints input_image requires an absolute HTTPS image URL without embedded credentials")
	}
	if fileID := text(part["file_id"]); fileID != "" {
		return fmt.Errorf("basispoints input_image does not support file_id; provide only an HTTPS image_url")
	}
	if detail, exists := part["detail"]; exists && detail != nil {
		switch text(detail) {
		case "auto", "low", "high":
		default:
			return fmt.Errorf("basispoints image detail must be auto, low or high")
		}
	}
	return nil
}
