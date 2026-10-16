package service

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/Wei-Shaw/sub2api/internal/pkg/devin"
)

// fetchDevinUpstreamModelList 按账号实时拉取 Devin 可用模型（GetCliModelConfigs，只读、不消耗额度），
// 聚合后的思考档位随同步写入账号快照，转发时据此拼出上游模型 UID。
func (s *AccountTestService) fetchDevinUpstreamModelList(ctx context.Context, account *Account) ([]string, []byte, error) {
	if s.httpUpstream == nil {
		return nil, nil, newUpstreamModelSyncConfigError("Upstream HTTP client is not configured", nil)
	}
	token := account.GetDevinSessionToken()
	if token == "" {
		return nil, nil, newUpstreamModelSyncConfigError("Devin session token is missing", nil)
	}
	baseURL, err := s.validateUpstreamBaseURL(account.GetDevinBaseURL())
	if err != nil {
		return nil, nil, newUpstreamModelSyncConfigError("Invalid Devin base URL", err)
	}
	req, err := devin.NewCliModelConfigsRequest(ctx, baseURL, token)
	if err != nil {
		return nil, nil, newUpstreamModelSyncConfigError("Failed to build Devin model list request", err)
	}
	resp, err := s.doUpstreamModelsRequest(req, upstreamModelsProxyURL(account), account)
	if err != nil {
		return nil, nil, newUpstreamModelSyncUpstreamError("Failed to request Devin model list", err)
	}
	defer func() { _ = resp.Body.Close() }()

	bodyLimit := resolveModelsListReadLimit(s.cfg)
	body, err := io.ReadAll(io.LimitReader(resp.Body, bodyLimit+1))
	if err != nil {
		return nil, nil, newUpstreamModelSyncUpstreamError("Failed to read Devin model list", err)
	}
	if int64(len(body)) > bodyLimit {
		return nil, nil, newUpstreamModelSyncUpstreamError("Devin model list response is too large", fmt.Errorf("response exceeds %d bytes", bodyLimit))
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil, &UpstreamModelSyncError{
			Kind:       UpstreamModelSyncErrorUpstream,
			Message:    fmt.Sprintf("Devin model list request failed with HTTP %d", resp.StatusCode),
			StatusCode: resp.StatusCode,
			Err:        fmt.Errorf("devin model list returned HTTP %d", resp.StatusCode),
		}
	}

	models, err := devin.ParseCliModelConfigs(body)
	if err != nil {
		return nil, nil, newUpstreamModelSyncUpstreamError("Devin model list response was not valid protobuf", err)
	}
	if len(models) == 0 {
		return nil, nil, newUpstreamModelSyncUpstreamError("Devin returned no supported models", nil)
	}
	catalog, err := devin.LiveModelsCatalogJSON(models)
	if err != nil {
		return nil, nil, newUpstreamModelSyncInternalError("Failed to encode Devin model list", err)
	}
	ids, err := extractUpstreamModelIDs(catalog)
	if err != nil {
		return nil, nil, newUpstreamModelSyncInternalError("Failed to read Devin model list", err)
	}
	return ids, catalog, nil
}
