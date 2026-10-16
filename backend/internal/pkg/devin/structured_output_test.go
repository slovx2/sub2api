package devin

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

const structuredRequestBody = `{"model":"gpt-6-1-sol","messages":[{"role":"system","content":"Draft a reply"},{"role":"user","content":"hi"}],
"response_format":{"type":"json_schema","json_schema":{"name":"MessageDraft","strict":true,"schema":{"type":"object","properties":{"reply":{"type":"string"}},"required":["reply"],"additionalProperties":false}}}}`

func TestNativeRequestEmulatesJSONSchemaWithStructuredTool(t *testing.T) {
	req, err := NewChatRequest(context.Background(), DevinDefaultBaseURL, "test", "session", []byte(structuredRequestBody), RequestOptions{})
	require.NoError(t, err)
	_, payload, err := ReadConnectFrame(req.Body)
	require.NoError(t, err)

	tools := byteFields(t, payload, 10)
	require.Len(t, tools, 1)
	require.Equal(t, StructuredOutputToolName, string(byteFields(t, tools[0], 1)[0]))
	require.Contains(t, string(byteFields(t, tools[0], 2)[0]), "MessageDraft")
	require.JSONEq(t, `{"type":"object","properties":{"reply":{"type":"string"}},"required":["reply"],"additionalProperties":false}`, string(byteFields(t, tools[0], 3)[0]))
	system := string(byteFields(t, payload, 2)[0])
	require.True(t, strings.HasPrefix(system, "Draft a reply\n"))
	require.Contains(t, system, StructuredOutputToolName)

	reserved := strings.Replace(structuredRequestBody, `"response_format"`, `"tools":[{"type":"function","function":{"name":"provide_structured_output"}}],"response_format"`, 1)
	_, err = NewChatRequest(context.Background(), DevinDefaultBaseURL, "test", "session", []byte(reserved), RequestOptions{})
	require.ErrorContains(t, err, "reserved")
}

func structuredToolFrames(argumentParts ...string) []byte {
	var frames []byte
	for i, part := range argumentParts {
		var tool []byte
		if i == 0 {
			tool = append(field(1, "call_structured"), field(2, StructuredOutputToolName)...)
		}
		tool = append(tool, field(3, part)...)
		frames = append(frames, frame(0, field(6, string(tool)))...)
	}
	return frames
}

func TestResponseTurnsStructuredToolCallIntoContent(t *testing.T) {
	data := bytes.Join([][]byte{
		frame(0, field(3, "Let me think. ")),
		structuredToolFrames(`{"reply":"你`, `好"}`),
		usageFrame(), frame(2, []byte(`{}`)),
	}, nil)

	resp, err := ConvertChatResponse(upstream(data), "gpt-6-1-sol", false, true)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, `{"reply":"你好"}`, gjson.GetBytes(body, "choices.0.message.content").String())
	require.False(t, gjson.GetBytes(body, "choices.0.message.tool_calls").Exists())
	require.Equal(t, "stop", gjson.GetBytes(body, "choices.0.finish_reason").String())

	resp, err = ConvertChatResponse(upstream(data), "gpt-6-1-sol", true, true)
	require.NoError(t, err)
	body, err = io.ReadAll(resp.Body)
	require.NoError(t, err)
	var content strings.Builder
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, "data: {") {
			chunk := gjson.Parse(strings.TrimPrefix(line, "data: "))
			require.False(t, chunk.Get("choices.0.delta.tool_calls").Exists())
			_, _ = content.WriteString(chunk.Get("choices.0.delta.content").String())
		}
	}
	require.Equal(t, `{"reply":"你好"}`, content.String())
}

func TestResponseStructuredFallbacks(t *testing.T) {
	jsonText := bytes.Join([][]byte{frame(0, field(3, " {\"reply\":\"ok\"}\n")), usageFrame(), frame(2, []byte(`{}`))}, nil)
	resp, err := ConvertChatResponse(upstream(jsonText), "gpt-6-1-sol", false, true)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, `{"reply":"ok"}`, gjson.GetBytes(body, "choices.0.message.content").String())

	plainText := bytes.Join([][]byte{frame(0, field(3, "Sure, here it is")), usageFrame(), frame(2, []byte(`{}`))}, nil)
	resp, err = ConvertChatResponse(upstream(plainText), "gpt-6-1-sol", false, true)
	require.NoError(t, err)
	require.Equal(t, 502, resp.StatusCode)
	body, err = io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Contains(t, string(body), "did not return structured output")

	invalidArgs := bytes.Join([][]byte{structuredToolFrames(`{"reply":`), usageFrame(), frame(2, []byte(`{}`))}, nil)
	resp, err = ConvertChatResponse(upstream(invalidArgs), "gpt-6-1-sol", false, true)
	require.NoError(t, err)
	require.Equal(t, 502, resp.StatusCode)
}
