package devin

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseDevinTrailerErrorStatus(t *testing.T) {
	cases := []struct {
		trailer string
		status  int
	}{
		// 请求内容被拒：按请求错误处理，不能落到 403 账号处罚。
		{`{"error":{"code":"permission_denied","message":"Unable to process request due to an MCP configuration issue. (trace ID: abc)"}}`, http.StatusBadRequest},
		{`{"error":{"code":"permission_denied","message":"Model is under high demand"}}`, http.StatusTooManyRequests},
		{`{"error":{"code":"permission_denied","message":"account suspended"}}`, http.StatusForbidden},
	}
	for _, tc := range cases {
		status, err := ParseDevinTrailerError([]byte(tc.trailer))
		require.Error(t, err)
		require.Equal(t, tc.status, status, tc.trailer)
	}
}
