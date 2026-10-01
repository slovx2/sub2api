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
	settings *service.SettingService
	queued   int
	cleared  bool
}

func (r *modelTraceHandlerRepo) UpdateSettings(ctx context.Context, cfg service.ModelTraceSettings, ids []int64) error {
	if err := r.settings.SaveModelTraceSettings(ctx, cfg); err != nil {
		return err
	}
	if !cfg.Enabled {
		return r.ClearQueue(ctx)
	}
	_, err := r.Enqueue(ctx, ids)
	return err
}

func (r *modelTraceHandlerRepo) Enqueue(_ context.Context, ids []int64) (service.ModelTraceQueueResult, error) {
	r.queued += len(ids)
	return service.ModelTraceQueueResult{Accepted: len(ids)}, nil
}
func (r *modelTraceHandlerRepo) ClearQueue(context.Context) error { r.cleared = true; return nil }
func TestModelTraceSettingsAndRunEndpoints(t *testing.T) {
	settings := service.NewSettingService(&modelTraceHandlerSettings{}, nil)
	repo := &modelTraceHandlerRepo{settings: settings}
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
	since := time.Now().Add(-48 * time.Hour)
	summary.Details[0].MatchedSince = &since
	withStreak := buildAccountsListETag(lite, 1, 1, 20, "openai", "oauth", "", "", true)
	require.NotEqual(t, after, withStreak)
	for _, rows := range []any{full, lite} {
		encoded, err := json.Marshal(rows)
		require.NoError(t, err)
		require.Equal(t, since.Format(time.RFC3339Nano), gjson.GetBytes(encoded, "0.modeltrace_summary.details.0.matched_since").String())
	}
	require.Equal(t, withStreak, buildAccountsListETag(lite, 1, 1, 20, "openai", "oauth", "", "", true))
}

type modelTraceHistoryHandlerRepo struct {
	service.ModelTraceRepository
	query service.ModelTraceHistoryQuery
	err   error
}

func (r *modelTraceHistoryHandlerRepo) History(_ context.Context, q service.ModelTraceHistoryQuery) (service.ModelTraceHistoryPage, error) {
	r.query = q
	return service.ModelTraceHistoryPage{Items: []service.ModelTraceHistoryEntry{}}, r.err
}
func TestModelTraceHistoryEndpoint(t *testing.T) {
	repo := &modelTraceHistoryHandlerRepo{}
	h := &AccountHandler{modeltrace: service.NewModelTraceService(nil, nil, repo, nil)}
	router := gin.New()
	router.GET("/history", h.GetModelTraceHistory)
	request := func(query string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest("GET", "/history"+query, nil))
		return rec
	}
	for _, query := range []string{"", "?account_id=0", "?account_id=1&protocol=invalid", "?account_id=1&cursor=invalid"} {
		require.Equal(t, 400, request(query).Code)
	}
	entry := service.ModelTraceHistoryEntry{ID: 42, ModelTraceResult: service.ModelTraceResult{FinishedAt: time.Now()}}
	rec := request("?account_id=7&protocol=bps&model=test&cursor=" + service.ModelTraceEncodeCursor(entry))
	require.Equal(t, 200, rec.Code)
	require.EqualValues(t, 7, repo.query.AccountID)
	require.Equal(t, "bps", repo.query.Protocol)
	require.Equal(t, "test", repo.query.Model)
	require.EqualValues(t, 42, repo.query.Before.ID)
	require.Equal(t, "[]", gjson.Get(rec.Body.String(), "data.items").Raw)
	repo.err = errors.New("history unavailable")
	require.Equal(t, 500, request("?account_id=7").Code)
}
