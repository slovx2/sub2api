package devin

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

// TestUsageBucketsMatchUpstreamAccounting 固定 Devin 上报的三个互不重叠桶的折算：
// prompt_tokens 记总输入，cached_tokens / cache_creation_tokens 记缓存明细。
// 真实上游实测：冷请求 uncached=3 / cache write=4044 / cache read=0，
// 同会话再发 uncached=3 / cache write=0 / cache read=4044，两次总输入都是 4047。
func TestUsageBucketsMatchUpstreamAccounting(t *testing.T) {
	cases := []struct {
		name              string
		prompt            int64
		write             int64
		read              int64
		wantPrompt        int64
		wantCached        int64
		wantCacheCreation int64
	}{
		{name: "冷请求", prompt: 3, write: 4044, read: 0, wantPrompt: 4047, wantCached: 0, wantCacheCreation: 4044},
		{name: "同会话命中缓存", prompt: 3, write: 0, read: 4044, wantPrompt: 4047, wantCached: 4044, wantCacheCreation: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			usage := bytes.Join([][]byte{
				number(2, uint64(tc.prompt)), number(3, 5), number(4, uint64(tc.write)),
				number(5, uint64(tc.read)), number(6, 66),
			}, nil)
			data := append(frame(0, field(7, string(usage))), frame(2, []byte("{}"))...)
			resp, err := ConvertChatResponse(upstream(data), "gpt-6-astra", false, false)
			require.NoError(t, err)
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			require.Equal(t, tc.wantPrompt, gjson.GetBytes(body, "usage.prompt_tokens").Int())
			require.Equal(t, tc.wantCached, gjson.GetBytes(body, "usage.prompt_tokens_details.cached_tokens").Int())
			require.Equal(t, tc.wantCacheCreation, gjson.GetBytes(body, "usage.prompt_tokens_details.cache_creation_tokens").Int())
			require.Equal(t, int64(5), gjson.GetBytes(body, "usage.completion_tokens").Int())
			require.Equal(t, tc.wantPrompt+5, gjson.GetBytes(body, "usage.total_tokens").Int())
		})
	}
}
