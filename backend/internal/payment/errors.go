package payment

import infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"

var (
	ErrPaymentDisabled  = infraerrors.Forbidden("PAYMENT_DISABLED", "payment is disabled")
	ErrInvalidAmount    = infraerrors.BadRequest("PAYMENT_INVALID_AMOUNT", "invalid amount")
	ErrInvalidChannel   = infraerrors.BadRequest("PAYMENT_INVALID_CHANNEL", "invalid payment channel")
	ErrInvalidDevice    = infraerrors.BadRequest("PAYMENT_INVALID_DEVICE", "invalid payment device")
	ErrOrderNotFound    = infraerrors.NotFound("PAYMENT_ORDER_NOT_FOUND", "payment order not found")
	ErrOrderForbidden   = infraerrors.Forbidden("PAYMENT_ORDER_FORBIDDEN", "payment order does not belong to user")
	ErrNotifyRejected   = infraerrors.BadRequest("PAYMENT_NOTIFY_REJECTED", "payment notify rejected")
	ErrSignatureInvalid = infraerrors.BadRequest("PAYMENT_SIGNATURE_INVALID", "payment signature invalid")
)
