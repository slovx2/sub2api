package service

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

func TestGPTImage26GenerationAndEdit(t *testing.T) {
	for _, model := range []string{"gpt-image-2.6-flare", "gpt-image-2.6-sunburst"} {
		for _, endpoint := range []string{"generations", "edits"} {
			for _, stream := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/stream=%t", model, endpoint, stream), func(t *testing.T) {
					body := []byte(fmt.Sprintf(`{"model":%q,"prompt":"蓝色圆形","complexity":"low","quality":"low","stream":%t,"images":[{"image_url":"data:image/png;base64,AA=="}]}`, model, stream))
					c, rec := newOpenAIImagesTestContext(t, body)
					c.Request.URL.Path = "/v1/images/" + endpoint
					response := openAIImagesJSONResponse()
					if stream {
						response = &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: io.NopCloser(strings.NewReader("data: {\"type\":\"image_generation.completed\",\"b64_json\":\"aGVsbG8=\",\"usage\":{\"input_tokens\":17,\"output_tokens\":343}}\n\n"))}
					}
					upstream := &httpUpstreamRecorder{resp: response}
					svc := newOpenAIImagesTestService(upstream)
					parsed, err := svc.ParseOpenAIImagesRequest(c, body)
					require.NoError(t, err)
					result, err := svc.ForwardImages(context.Background(), c, directImagesTestAccount(), body, parsed, "")
					require.NoError(t, err)
					require.Equal(t, 1, result.ImageCount)
					require.Equal(t, model, result.UpstreamModel)
					require.Equal(t, "/backend-api/codex/images/"+endpoint, upstream.lastReq.URL.Path)
					require.Equal(t, "low", gjson.GetBytes(upstream.lastBody, "complexity").String())
					require.Equal(t, model, gjson.GetBytes(upstream.lastBody, "model").String())
					if endpoint == "edits" {
						require.Equal(t, "data:image/png;base64,AA==", gjson.GetBytes(upstream.lastBody, "images.0.image_url").String())
					}
					if stream {
						require.Equal(t, 343, result.Usage.ImageOutputTokens)
						require.Contains(t, rec.Body.String(), ".completed")
					} else {
						require.Equal(t, "aGVsbG8=", gjson.GetBytes(rec.Body.Bytes(), "data.0.b64_json").String())
					}
				})
			}
		}
	}
}

func TestGPTImage26ComplexityValidation(t *testing.T) {
	for _, complexity := range []string{`"low"`, `"medium"`, `"high"`, `"auto"`, `"max"`, `1`, `true`} {
		t.Run(complexity, func(t *testing.T) {
			body := []byte(fmt.Sprintf(`{"model":"gpt-image-2.6-flare","prompt":"draw","complexity":%s}`, complexity))
			c, _ := newOpenAIImagesTestContext(t, body)
			parsed, err := newOpenAIImagesTestService(nil).ParseOpenAIImagesRequest(c, body)
			if complexity == `"low"` || complexity == `"medium"` || complexity == `"high"` {
				require.NoError(t, err)
				require.True(t, parsed.HasNativeOptions)
			} else {
				require.ErrorContains(t, err, "complexity")
			}
		})
	}
}
