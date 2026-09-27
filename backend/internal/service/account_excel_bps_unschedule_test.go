package service

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

type excelBPSUnscheduleRepo struct {
	excelBPSAutoDisableRepo
	unschedule func(context.Context, *Account) (bool, error)
}

func (r *excelBPSUnscheduleRepo) UnscheduleExcelBPSOn403(ctx context.Context, account *Account) (bool, error) {
	return r.unschedule(ctx, account)
}

func TestExcelBPSUnscheduleOn403Flag(t *testing.T) {
	require.False(t, (*Account)(nil).IsExcelBPSUnscheduleOn403Enabled())
	account := excelAccount()
	require.True(t, account.IsExcelBPSUnscheduleOn403Enabled(), "默认打开")
	account.Extra[ExcelBPSUnscheduleOn403Key] = false
	require.False(t, account.IsExcelBPSUnscheduleOn403Enabled(), "显式关闭才生效")
	account.Extra[ExcelBPSUnscheduleOn403Key] = true
	require.True(t, account.IsExcelBPSUnscheduleOn403Enabled())
	account.Extra["openai_excel_bps"] = false
	require.False(t, account.IsExcelBPSUnscheduleOn403Enabled(), "关闭 BPS 后开关不再生效")
}

func TestMergeExcelBPS403Marker(t *testing.T) {
	const at = "2026-09-27T10:00:00Z"
	previous := map[string]any{ExcelBPS403DisabledAtKey: at}

	next := map[string]any{"openai_excel_bps": false}
	MergeExcelBPS403Marker(previous, next)
	require.Equal(t, at, next[ExcelBPS403DisabledAtKey], "普通编辑必须保留标记")

	next = map[string]any{"openai_excel_bps": true}
	MergeExcelBPS403Marker(previous, next)
	require.NotContains(t, next, ExcelBPS403DisabledAtKey, "重新开启协议要清除标记")

	next = map[string]any{"openai_excel_bps": false, ExcelBPS403DisabledAtKey: "2000-01-01T00:00:00Z"}
	MergeExcelBPS403Marker(previous, next)
	require.Equal(t, at, next[ExcelBPS403DisabledAtKey], "忽略请求带来的标记值")
}

// 开启“403 后停止调度”时：只调用账号级停止调度，不再走分组动作 / 仅关闭协议，并回显对应文案。
func TestExcelBPS403UnscheduleAction(t *testing.T) {
	for _, tc := range []struct {
		name         string
		extra        any
		wantActions  []string
		wantContains string
	}{
		{name: "默认打开", extra: nil, wantActions: []string{"unschedule"}, wantContains: "taken out of scheduling"},
		{name: "显式打开", extra: true, wantActions: []string{"unschedule"}, wantContains: "taken out of scheduling"},
		{name: "显式关闭回退到仅关闭协议", extra: false, wantActions: []string{"disable"}, wantContains: "automatically disabled for this account"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			account := excelAccount()
			account.GroupIDs = []int64{1, 2}
			account.Extra["openai_excel_bps_auto_disable_on_403"] = true
			if tc.extra != nil {
				account.Extra[ExcelBPSUnscheduleOn403Key] = tc.extra
			}
			upstream := &httpUpstreamRecorder{resp: &http.Response{
				StatusCode: http.StatusForbidden, Header: http.Header{},
				Body: io.NopCloser(strings.NewReader(`{"error":{"code":"permission_denied"}}`)),
			}}
			svc := openAIClientToolsTestService(upstream)
			var actions []string
			svc.accountRepo = &excelBPSUnscheduleRepo{
				excelBPSAutoDisableRepo: excelBPSAutoDisableRepo{disable: func(context.Context, *Account) (bool, error) {
					actions = append(actions, "disable")
					return true, nil
				}},
				unschedule: func(ctx context.Context, got *Account) (bool, error) {
					require.NoError(t, ctx.Err())
					_, bounded := ctx.Deadline()
					require.True(t, bounded)
					require.True(t, got.IsExcelBPSUnscheduleOn403Enabled())
					actions = append(actions, "unschedule")
					return true, nil
				},
			}
			rec := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(rec)
			c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
			_, err := svc.Forward(context.Background(), c, account, []byte(`{"model":"gpt-6-astra","stream":true,"input":"test"}`))
			require.Error(t, err)
			require.Equal(t, tc.wantActions, actions)
			require.Contains(t, rec.Body.String(), tc.wantContains)
		})
	}
}
