package devin

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/pkg/apicompat"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
	"google.golang.org/protobuf/encoding/protowire"
)

func field(n protowire.Number, value string) []byte {
	return protowire.AppendString(protowire.AppendTag(nil, n, protowire.BytesType), value)
}
func number(n protowire.Number, value uint64) []byte {
	return protowire.AppendVarint(protowire.AppendTag(nil, n, protowire.VarintType), value)
}
func frame(flag byte, payload []byte) []byte {
	b := make([]byte, 5, len(payload)+5)
	b[0] = flag
	binary.BigEndian.PutUint32(b[1:], uint32(len(payload)))
	return append(b, payload...)
}
func usageFrame() []byte {
	u := bytes.Join([][]byte{number(2, 7), number(3, 3), number(4, 2), number(5, 5), number(6, 200)}, nil)
	return frame(0, field(7, string(u)))
}
func upstream(body []byte) *http.Response {
	return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(body))}
}
func byteFields(t *testing.T, payload []byte, tag protowire.Number) [][]byte {
	t.Helper()
	var found [][]byte
	for len(payload) > 0 {
		n, typ, size := protowire.ConsumeTag(payload)
		require.Positive(t, size)
		payload = payload[size:]
		if typ == protowire.BytesType {
			v, size := protowire.ConsumeBytes(payload)
			require.Positive(t, size)
			if n == tag {
				found = append(found, v)
			}
			payload = payload[size:]
		} else {
			size := protowire.ConsumeFieldValue(n, typ, payload)
			require.Positive(t, size)
			payload = payload[size:]
		}
	}
	return found
}

func TestNativeRequestPreservesSystemToolsAndSignature(t *testing.T) {
	id := EncodeDevinToolCallID("call/中文")
	sig := packSignature([]byte("sealed.v1.test"), "sealed")
	body := `{"model":"gpt-5.4","reasoning_effort":"high","messages":[{"role":"system","content":"Do not change my system instructions"},{"role":"user","content":"hello"},{"role":"assistant","reasoning_content":"plan","reasoning_signature":"` + sig + `","tool_calls":[{"id":"` + id + `","type":"function","function":{"name":"lookup","arguments":"{}"}}]},{"role":"tool","tool_call_id":"` + id + `","content":"done"}],"tools":[{"type":"function","function":{"name":"lookup","description":"Original tool description","parameters":{"type":"object"}}}]}`
	req, err := NewChatRequest(context.Background(), DevinDefaultBaseURL, "devin-session-token$test", "isolated-session", []byte(body), RequestOptions{})
	require.NoError(t, err)
	require.Equal(t, DevinDefaultBaseURL+DevinChatPath, req.URL.String())
	require.Equal(t, "Basic devin-session-token$test-devin-session-token$test", req.Header.Get("Authorization"))
	require.Equal(t, "application/connect+proto", req.Header.Get("Content-Type"))
	_, payload, err := ReadConnectFrame(req.Body)
	require.NoError(t, err)
	require.Equal(t, "Do not change my system instructions", string(byteFields(t, payload, 2)[0]))
	require.Equal(t, "gpt-5-4-high", string(byteFields(t, payload, 21)[0]))
	prompts := byteFields(t, payload, 3)
	require.Len(t, prompts, 3)
	require.Equal(t, "sealed.v1.test", string(byteFields(t, prompts[1], 12)[0]))
	require.Equal(t, "sealed", string(byteFields(t, prompts[1], 18)[0]))
	require.Equal(t, "call/中文", string(byteFields(t, prompts[2], 7)[0]))
	require.Contains(t, string(payload), "Original tool description")
}

func TestResponseSplitUTF8ToolsLateSignatureAndUsage(t *testing.T) {
	tool := bytes.Join([][]byte{field(1, "call/一"), field(2, "lookup"), field(3, `{"q":`)}, nil)
	data := bytes.Join([][]byte{
		frame(0, field(9, string([]byte("思考")[:2]))), frame(0, field(9, string([]byte("思考")[2:]))),
		frame(0, field(6, string(tool))), frame(0, field(6, string(field(3, `"ok"}`)))),
		frame(0, field(10, "sealed.v1.")), frame(0, append(field(10, "test"), field(21, "sealed")...)),
		usageFrame(), frame(2, []byte(`{}`)),
	}, nil)
	for _, stream := range []bool{false, true} {
		resp, err := ConvertChatResponse(upstream(data), "gpt-5.4", stream, false)
		require.NoError(t, err)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Equal(t, 200, resp.StatusCode)
		if !stream {
			require.Equal(t, "思考", gjson.GetBytes(body, "choices.0.message.reasoning_content").String())
			require.Equal(t, `{"q":"ok"}`, gjson.GetBytes(body, "choices.0.message.tool_calls.0.function.arguments").String())
			require.Equal(t, int64(12), gjson.GetBytes(body, "usage.prompt_tokens").Int())
			require.Equal(t, int64(2), gjson.GetBytes(body, "usage.prompt_tokens_details.cache_creation_tokens").Int())
			continue
		}
		require.Less(t, strings.Index(string(body), "reasoning_signature"), strings.Index(string(body), "tool_calls"))
		require.Contains(t, string(body), "data: [DONE]")
		responses := apicompat.NewChatCompletionsToResponsesStreamState("gpt-5.4")
		anthropic := apicompat.NewChatCompletionsToAnthropicStreamState("gpt-5.4")
		var events []apicompat.AnthropicStreamEvent
		for _, line := range strings.Split(string(body), "\n") {
			if !strings.HasPrefix(line, "data: {") {
				continue
			}
			var chunk apicompat.ChatCompletionsChunk
			require.NoError(t, json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &chunk))
			apicompat.ChatCompletionsChunkToResponsesEvents(&chunk, responses)
			events = append(events, apicompat.ChatCompletionsChunkToAnthropicEvents(&chunk, anthropic)...)
		}
		require.NotEmpty(t, responses.ReasoningSignature)
		var gotSignature bool
		for _, event := range events {
			if event.Delta != nil && event.Delta.Signature != "" {
				gotSignature = true
			}
		}
		require.True(t, gotSignature)
		sig, kind, err := unpackSignature(responses.ReasoningSignature)
		require.NoError(t, err)
		require.Equal(t, "sealed", kind)
		require.Equal(t, "sealed.v1.test", string(sig))
	}
}

func TestResponseRejectsErrorsAndTruncation(t *testing.T) {
	for name, data := range map[string][]byte{
		"missing usage":       frame(2, []byte(`{}`)),
		"invalid terminal":    append(usageFrame(), frame(2, []byte(`broken`))...),
		"truncated":           append(frame(0, field(3, "hi")), []byte{0, 0}...),
		"missing terminal":    usageFrame(),
		"invalid nested tool": frame(0, field(6, string([]byte{255}))),
	} {
		t.Run(name, func(t *testing.T) {
			resp, err := ConvertChatResponse(upstream(data), "swe-2", false, false)
			require.NoError(t, err)
			require.Equal(t, 502, resp.StatusCode)
		})
	}
	resp, err := ConvertChatResponse(upstream(frame(2, []byte(`{"error":{"code":"resource_exhausted","message":"quota exhausted"}}`))), "swe-2", true, false)
	require.NoError(t, err)
	require.Equal(t, 429, resp.StatusCode)
	resp, err = ConvertChatResponse(upstream(append(frame(0, field(3, "hi")), frame(2, []byte(`{"error":{"code":"unavailable"}}`))...)), "swe-2", true, false)
	require.NoError(t, err)
	b, err := io.ReadAll(resp.Body)
	require.Error(t, err)
	require.NotContains(t, string(b), "[DONE]")
}

func TestCompressedAndInvalidFrames(t *testing.T) {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	_, err := w.Write(field(3, "中文"))
	require.NoError(t, err)
	require.NoError(t, w.Close())
	flag, payload, err := ReadConnectFrame(bytes.NewReader(frame(1, b.Bytes())))
	require.NoError(t, err)
	require.Equal(t, byte(1), flag)
	parsed, err := ParseDevinFrame(payload)
	require.NoError(t, err)
	require.Equal(t, "中文", parsed.ContentText)
	for _, data := range [][]byte{{7, 0, 0, 0, 0}, {0, 127, 255, 255, 255}, frame(1, []byte("bad gzip"))} {
		_, _, err := ReadConnectFrame(bytes.NewReader(data))
		require.Error(t, err)
	}
}

func TestSignaturePassbackAcrossClientProtocols(t *testing.T) {
	sig := packSignature([]byte("opaque"), "openai")
	var response apicompat.ResponsesRequest
	require.NoError(t, json.Unmarshal([]byte(`{"model":"gpt-5.4","input":[{"type":"reasoning","summary":[{"type":"summary_text","text":"plan"}],"encrypted_content":"`+sig+`"},{"type":"function_call","call_id":"call_a","name":"lookup","arguments":"{}"},{"type":"function_call_output","call_id":"call_a","output":"ok"}]}`), &response))
	cc, err := apicompat.ResponsesToChatCompletionsRequest(&response)
	require.NoError(t, err)
	require.Equal(t, sig, cc.Messages[0].ReasoningSignature)
	var anthropic apicompat.AnthropicRequest
	require.NoError(t, json.Unmarshal([]byte(`{"model":"gpt-5.4","messages":[{"role":"assistant","content":[{"type":"thinking","thinking":"plan","signature":"`+sig+`"},{"type":"tool_use","id":"call_a","name":"lookup","input":{}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"call_a","content":"ok"}]}]}`), &anthropic))
	cc, err = apicompat.AnthropicToChatCompletionsRequest(&anthropic)
	require.NoError(t, err)
	require.Equal(t, sig, cc.Messages[0].ReasoningSignature)
}

func TestToolArgumentsUTF8SplitAndRepeatedName(t *testing.T) {
	arguments := []byte(`{"城市":"北京"}`)
	var frames []byte
	for i, b := range arguments {
		var tool []byte
		if i == 0 {
			tool = field(1, "call_a")
		}
		tool = append(tool, field(2, "lookup")...)
		tool = append(tool, field(3, string([]byte{b}))...)
		frames = append(frames, frame(0, field(6, string(tool)))...)
	}
	frames = append(frames, usageFrame()...)
	frames = append(frames, frame(2, []byte(`{}`))...)
	resp, err := ConvertChatResponse(upstream(frames), "swe-2", true, false)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	var name, args strings.Builder
	for _, line := range strings.Split(string(body), "\n") {
		if !strings.HasPrefix(line, "data: {") {
			continue
		}
		value := gjson.Parse(strings.TrimPrefix(line, "data: ")).Get("choices.0.delta.tool_calls.0.function")
		name.WriteString(value.Get("name").String())
		args.WriteString(value.Get("arguments").String())
	}
	require.Equal(t, "lookup", name.String())
	require.Equal(t, string(arguments), args.String())
}

func TestRequestImagesAndUnsupportedOptions(t *testing.T) {
	body := `{"model":"swe-2","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:image/png;base64,aW1hZ2U="}}]}]}`
	req, err := NewChatRequest(context.Background(), DevinDefaultBaseURL, "test", "test", []byte(body), RequestOptions{})
	require.NoError(t, err)
	_, payload, err := ReadConnectFrame(req.Body)
	require.NoError(t, err)
	require.Contains(t, string(payload), "aW1hZ2U=")
	for _, invalid := range []string{
		strings.Replace(body, "data:image/png;base64,aW1hZ2U=", "https://example.com/image.png", 1),
		strings.Replace(body, `"model":`, `"n":2,"model":`, 1),
		strings.Replace(body, `"model":`, `"tool_choice":"required","model":`, 1),
		strings.Replace(body, `"model":`, `"response_format":{"type":"json_object"},"model":`, 1),
	} {
		_, err := NewChatRequest(context.Background(), DevinDefaultBaseURL, "test", "test", []byte(invalid), RequestOptions{})
		require.Error(t, err)
	}
	for _, id := range []string{"call_normal", "call/中文", "cpa_tid_v1_raw", "call with space"} {
		require.Equal(t, id, DecodeDevinToolCallID(EncodeDevinToolCallID(id)))
	}
}
