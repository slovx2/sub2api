package service

import "strings"

const (
	SettingPaymentEnabled      = "payment_enabled"
	SettingMinRechargeAmount   = "MIN_RECHARGE_AMOUNT"
	SettingMaxRechargeAmount   = "MAX_RECHARGE_AMOUNT"
	SettingDailyRechargeLimit  = "DAILY_RECHARGE_LIMIT"
	SettingOrderTimeoutMinutes = "ORDER_TIMEOUT_MINUTES"
	SettingMaxPendingOrders    = "MAX_PENDING_ORDERS"
	SettingEnabledPaymentTypes = "ENABLED_PAYMENT_TYPES"
	SettingLoadBalanceStrategy = "LOAD_BALANCE_STRATEGY"
	SettingBalancePayDisabled  = "BALANCE_PAYMENT_DISABLED"
	SettingBalanceRechargeMult = "BALANCE_RECHARGE_MULTIPLIER"
	SettingRechargeFeeRate     = "RECHARGE_FEE_RATE"
	SettingProductNamePrefix   = "PRODUCT_NAME_PREFIX"
	SettingProductNameSuffix   = "PRODUCT_NAME_SUFFIX"
	SettingHelpImageURL        = "PAYMENT_HELP_IMAGE_URL"
	SettingHelpText            = "PAYMENT_HELP_TEXT"
	SettingCancelRateLimitOn   = "CANCEL_RATE_LIMIT_ENABLED"
	SettingCancelRateLimitMax  = "CANCEL_RATE_LIMIT_MAX"
	SettingCancelWindowSize    = "CANCEL_RATE_LIMIT_WINDOW"
	SettingCancelWindowUnit    = "CANCEL_RATE_LIMIT_UNIT"
	SettingCancelWindowMode    = "CANCEL_RATE_LIMIT_WINDOW_MODE"

	SettingPaymentVisibleMethodAlipaySource  = "payment_visible_method_alipay_source"
	SettingPaymentVisibleMethodWxpaySource   = "payment_visible_method_wxpay_source"
	SettingPaymentVisibleMethodAlipayEnabled = "payment_visible_method_alipay_enabled"
	SettingPaymentVisibleMethodWxpayEnabled  = "payment_visible_method_wxpay_enabled"

	VisibleMethodSourceOfficialAlipay = "official_alipay"
	VisibleMethodSourceEasyPayAlipay  = "easypay_alipay"
	VisibleMethodSourceOfficialWechat = "official_wxpay"
	VisibleMethodSourceEasyPayWechat  = "easypay_wxpay"
)

func NormalizeVisibleMethod(method string) string {
	switch strings.TrimSpace(strings.ToLower(method)) {
	case "alipay", "alipay_direct":
		return "alipay"
	case "wxpay", "wxpay_direct", "wechat":
		return "wxpay"
	default:
		return strings.TrimSpace(strings.ToLower(method))
	}
}

func NormalizeVisibleMethodSource(method, source string) string {
	switch NormalizeVisibleMethod(method) {
	case "alipay":
		switch strings.TrimSpace(strings.ToLower(source)) {
		case VisibleMethodSourceOfficialAlipay, "alipay", "alipay_direct", "official":
			return VisibleMethodSourceOfficialAlipay
		case VisibleMethodSourceEasyPayAlipay, "easypay":
			return VisibleMethodSourceEasyPayAlipay
		}
	case "wxpay":
		switch strings.TrimSpace(strings.ToLower(source)) {
		case VisibleMethodSourceOfficialWechat, "wxpay", "wxpay_direct", "wechat", "official":
			return VisibleMethodSourceOfficialWechat
		case VisibleMethodSourceEasyPayWechat, "easypay":
			return VisibleMethodSourceEasyPayWechat
		}
	}
	return ""
}
