package admin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

type modelTraceHandlerSettings struct {
	service.SettingRepository
	value string
	err   error
}

func (r *modelTraceHandlerSettings) GetValue(context.Context, string) (string, error) {
	return r.value, r.err
}

type modelTraceFailingSummaryRepo struct {
	service.ModelTraceRepository
	stage string
}

func (r modelTraceFailingSummaryRepo) Latest(context.Context, []int64) (map[int64][]service.ModelTraceResult, error) {
	if r.stage == "results" {
		return nil, errors.New("探测结果不可用")
	}
	return nil, nil
}
func (r modelTraceFailingSummaryRepo) States(context.Context, []int64) (map[int64]service.ModelTraceState, error) {
	return nil, errors.New("探测状态不可用")
}

func TestModelTraceSummaryFailureDoesNotBreakAccountList(t *testing.T) {
	for _, stage := range []string{"settings", "results", "states"} {
		for _, lite := range []string{"0", "1"} {
			t.Run(stage+"/lite="+lite, func(t *testing.T) {
				cfg := service.DefaultModelTraceSettings()
				cfg.Targets = []service.ModelTraceTarget{{Protocol: "codex", Model: "model"}}
				raw, err := json.Marshal(cfg)
				require.NoError(t, err)
				settingsRepo := &modelTraceHandlerSettings{value: string(raw)}
				if stage == "settings" {
					settingsRepo.err = errors.New("探测设置不可用")
				}
				svc := service.NewModelTraceService(service.NewSettingService(settingsRepo, nil), modelTraceHandlerAccounts{}, modelTraceFailingSummaryRepo{stage: stage}, nil)
				adminSvc := newStubAdminService()
				adminSvc.accounts = []service.Account{{ID: 1, Name: "test", Platform: service.PlatformOpenAI, Type: service.AccountTypeOAuth}}
				handler := NewAccountHandler(adminSvc, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
				handler.modeltrace = svc
				router := gin.New()
				router.GET("/accounts", handler.List)
				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/accounts?lite="+lite, nil))
				require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
				require.EqualValues(t, 1, gjson.Get(rec.Body.String(), "data.items.0.id").Int())
				require.NotContains(t, rec.Body.String(), "modeltrace_summary")
				require.NotEmpty(t, rec.Header().Get("ETag"))
			})
		}
	}
}
func (r *modelTraceHandlerSettings) Set(_ context.Context, _ string, value string) error {
	r.value = value
	return nil
}

type modelTraceHandlerAccounts struct{ service.AccountRepository }

func (modelTraceHandlerAccounts) ListAllWithFilters(context.Context, string, string, string, string, int64, string) ([]service.Account, error) {
	return []service.Account{{ID: 1, Name: "ordinary", Platform: "openai", Type: "oauth", Status: "active", Credentials: map[string]any{"access_token": "never-expose"}}, {ID: 2, Name: "key", Platform: "openai", Type: "apikey"}}, nil
}

type modelTraceHandlerRepo struct {
	service.ModelTraceRepository
	queued  int
	cleared bool
}

func (r *modelTraceHandlerRepo) Enqueue(_ context.Context, ids []int64) (service.ModelTraceQueueResult, error) {
	r.queued += len(ids)
	return service.ModelTraceQueueResult{Accepted: len(ids)}, nil
}
func (r *modelTraceHandlerRepo) ClearQueue(context.Context) error { r.cleared = true; return nil }
func TestModelTraceSettingsAndRunEndpoints(t *testing.T) {
	settings := service.NewSettingService(&modelTraceHandlerSettings{}, nil)
	repo := &modelTraceHandlerRepo{}
	svc := service.NewModelTraceService(settings, modelTraceHandlerAccounts{}, repo, nil)
	accountHandler := &AccountHandler{modeltrace: svc}
	router := gin.New()
	router.GET("/settings", accountHandler.GetModelTraceSettings)
	router.PUT("/settings", accountHandler.SaveModelTraceSettings)
	router.POST("/run", accountHandler.RunModelTrace)
	request := func(method, path, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(rec, req)
		return rec
	}
	rec := request(http.MethodGet, "/settings", "")
	require.Equal(t, 200, rec.Code)
	require.Equal(t, int64(30), gjson.Get(rec.Body.String(), "data.config.interval_minutes").Int())
	require.Len(t, gjson.Get(rec.Body.String(), "data.candidates").Array(), 13)
	require.Len(t, gjson.Get(rec.Body.String(), "data.accounts").Array(), 1)
	require.NotContains(t, rec.Body.String(), "never-expose")
	require.Equal(t, 400, request(http.MethodPost, "/run", "").Code)
	cfg := service.DefaultModelTraceSettings()
	cfg.Enabled = true
	cfg.AccountMode = "all"
	cfg.Targets = []service.ModelTraceTarget{{Protocol: "bps", Model: " custom-model ", Expected: " gpt-6-astra "}}
	raw, _ := json.Marshal(cfg)
	rec = request(http.MethodPut, "/settings", string(raw))
	require.Equal(t, 200, rec.Code, rec.Body.String())
	require.Equal(t, 1, repo.queued)
	rec = request(http.MethodGet, "/settings", "")
	require.Equal(t, "custom-model", gjson.Get(rec.Body.String(), "data.config.targets.0.model").String())
	require.Equal(t, "gpt-6-astra", gjson.Get(rec.Body.String(), "data.config.targets.0.expected_model").String())
	require.Equal(t, 200, request(http.MethodPost, "/run", "").Code)
	require.Equal(t, 2, repo.queued)
	cfg.IntervalMinutes = 9
	raw, _ = json.Marshal(cfg)
	require.Equal(t, 400, request(http.MethodPut, "/settings", string(raw)).Code)
	cfg.IntervalMinutes = 30
	cfg.Enabled = false
	raw, _ = json.Marshal(cfg)
	require.Equal(t, 200, request(http.MethodPut, "/settings", string(raw)).Code)
	require.True(t, repo.cleared)
}
func TestModelTraceSummaryIncludedInListETag(t *testing.T) {
	summary := &service.ModelTraceSummary{Matched: 1, Details: []service.ModelTraceDetail{{ModelTraceResult: service.ModelTraceResult{Protocol: "codex", Model: "custom", Status: "success", FinishedAt: time.Now()}}}}
	full := []AccountWithConcurrency{{ModelTraceSummary: summary}}
	lite := []AccountListItemWithConcurrency{{ModelTraceSummary: summary}}
	raw, err := json.Marshal(full)
	require.NoError(t, err)
	require.EqualValues(t, 1, gjson.GetBytes(raw, "0.modeltrace_summary.matched").Int())
	before := buildAccountsListETag(lite, 1, 1, 20, "openai", "oauth", "", "", true)
	summary.Matched = 0
	summary.Mismatched = 1
	after := buildAccountsListETag(lite, 1, 1, 20, "openai", "oauth", "", "", true)
	require.NotEqual(t, before, after)
}
