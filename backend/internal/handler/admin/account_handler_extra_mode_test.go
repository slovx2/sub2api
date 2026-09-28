package admin

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// A partial extra payload must never wipe unrelated runtime keys, so the update
// endpoint merges by default and only a full snapshot asks for replace.
func TestAccountHandlerUpdateExtraMode(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{"partial payload defaults to merge", `{"extra":{"email":"user@example.com"}}`, "merge"},
		{"explicit merge keeps patch semantics", `{"extra":{"email":"user@example.com"},"extra_mode":"merge"}`, "merge"},
		{"full snapshot opts into replace", `{"extra":{"email":"user@example.com"},"extra_mode":"replace"}`, "replace"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			adminSvc := newStubAdminService()
			router := setupAccountMixedChannelRouter(adminSvc)

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/accounts/7", bytes.NewReader([]byte(tc.body)))
			req.Header.Set("Content-Type", "application/json")
			router.ServeHTTP(rec, req)

			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			require.NotNil(t, adminSvc.lastUpdateAccountInput)
			require.Equal(t, tc.want, adminSvc.lastUpdateAccountInput.ExtraMode)
		})
	}
}

func TestAccountHandlerUpdateRejectsUnknownExtraMode(t *testing.T) {
	adminSvc := newStubAdminService()
	router := setupAccountMixedChannelRouter(adminSvc)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/v1/admin/accounts/7", bytes.NewReader([]byte(`{"extra":{"email":"x@example.com"},"extra_mode":"overwrite"}`)))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Nil(t, adminSvc.lastUpdateAccountInput)
}
