package service

import (
	"context"
	"time"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
)

const (
	// ExcelBPSUnscheduleOn403Key 打开后，BPS 返回 403 时直接把账号设为不可调度
	// （账号级一键开关，分组绑定保持不动，方便人工恢复）。
	ExcelBPSUnscheduleOn403Key = "openai_excel_bps_unschedule_on_403"
	// ExcelBPS403DisabledAtKey 记录因 403 自动停止调度的时间（UTC RFC3339），
	// 与上游同名；重新打开调度开关时清除。
	ExcelBPS403DisabledAtKey = "openai_excel_bps_403_disabled_at"
)

// IsExcelBPSUnscheduleOn403Enabled 判断账号是否开启“403 后停止调度”。
// 该保护默认打开：只有显式写入 false 才会关闭。
func (a *Account) IsExcelBPSUnscheduleOn403Enabled() bool {
	if a == nil || !a.IsExcelBPSEnabled() {
		return false
	}
	value, exists := a.Extra[ExcelBPSUnscheduleOn403Key]
	if !exists || value == nil {
		return true
	}
	enabled, ok := value.(bool)
	if !ok {
		// 非法值按默认（打开）处理，避免因为脏数据让被拦截的账号继续被打。
		return true
	}
	return enabled
}

// ExcelBPS403MarkerTime 解析标记时间，无效时返回 false。
func ExcelBPS403MarkerTime(extra map[string]any) (time.Time, bool) {
	if extra == nil {
		return time.Time{}, false
	}
	value, ok := extra[ExcelBPS403DisabledAtKey].(string)
	if !ok {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, false
	}
	return parsed, true
}

// MergeExcelBPS403Marker 让 403 标记在普通编辑中保留，并且忽略编辑请求里带来的标记值。
// 清除时机是“重新打开账号调度”（见 ClearExcelBPS403Marker）。
func MergeExcelBPS403Marker(previous, next map[string]any) {
	if next == nil {
		return
	}
	delete(next, ExcelBPS403DisabledAtKey)
	value, exists := previous[ExcelBPS403DisabledAtKey]
	if !exists {
		return
	}
	next[ExcelBPS403DisabledAtKey] = value
}

// ClearExcelBPS403Marker 在人工恢复调度后清掉标记。
func ClearExcelBPS403Marker(extra map[string]any) {
	delete(extra, ExcelBPS403DisabledAtKey)
}

func validateExcelBPS403ActionExtra(extra map[string]any) error {
	invalid := func(message string) error {
		return infraerrors.BadRequest("OPENAI_EXCEL_BPS_INVALID", message)
	}
	if raw, exists := extra[ExcelBPSUnscheduleOn403Key]; exists {
		if _, ok := raw.(bool); !ok {
			return invalid(ExcelBPSUnscheduleOn403Key + " must be a boolean")
		}
	}
	if raw, exists := extra[ExcelBPS403DisabledAtKey]; exists && raw != nil {
		if _, ok := raw.(string); !ok {
			return invalid(ExcelBPS403DisabledAtKey + " must be an RFC 3339 string")
		}
	}
	return nil
}

// validateExcelBPS403Actions 校验 BPS 403 处置配置（默认打开 + 标记类型）。
func (s *adminServiceImpl) validateExcelBPS403Actions(_ context.Context, account *Account) error {
	if err := validateExcelBPS403ActionExtra(account.Extra); err != nil {
		return err
	}
	// 只有显式打开时才要求账号形态匹配（默认打开不阻塞其它类型账号保存）。
	if enabled, _ := account.Extra[ExcelBPSUnscheduleOn403Key].(bool); enabled &&
		(account.Platform != PlatformOpenAI || account.Type != AccountTypeOAuth || account.IsShadow()) {
		return infraerrors.BadRequest("OPENAI_EXCEL_BPS_INVALID", "BPS 403 unschedule requires an OpenAI ChatGPT OAuth account")
	}
	return nil
}
