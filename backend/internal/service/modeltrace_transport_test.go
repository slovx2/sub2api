package service

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/tlsfingerprint"
	"github.com/stretchr/testify/require"
)

// 未实现的账号写入方法经 nil 接口调用立即 panic，确保任何状态副作用都会使测试失败。
type probeAccountRepo struct {
	AccountRepository
	account *Account
	writes  int
}

func (r *probeAccountRepo) GetByID(context.Context, int64) (*Account, error) {
	a := *r.account
	a.Credentials = shallowCopyMap(r.account.Credentials)
	a.Extra = shallowCopyMap(r.account.Extra)
	return &a, nil
}
func (r *probeAccountRepo) ListAllWithFilters(context.Context, string, string, string, string, int64, string) ([]Account, error) {
	return []Account{*r.account}, nil
}

type probeHTTP struct {
	HTTPUpstream
	status  int
	body    string
	err     error
	request *http.Request
	proxy   string
}

func (p *probeHTTP) Do(req *http.Request, proxy string, _ int64, _ int) (*http.Response, error) {
	p.request = req
	p.proxy = proxy
	if p.err != nil {
		return nil, p.err
	}
	return &http.Response{StatusCode: p.status, Header: http.Header{"X-Codex-Primary-Used-Percent": []string{"100"}}, Body: io.NopCloser(strings.NewReader(p.body))}, nil
}
func (p *probeHTTP) DoWithTLS(req *http.Request, proxy string, id int64, n int, _ *tlsfingerprint.Profile) (*http.Response, error) {
	return p.Do(req, proxy, id, n)
}
func probeTestAccount() *Account {
	return &Account{ID: 42, Platform: PlatformOpenAI, Type: AccountTypeOAuth, Status: StatusActive, Schedulable: true, Credentials: map[string]any{"access_token": "access", "refresh_token": "refresh", "chatgpt_account_id": "account-42", "expires_at": time.Now().Add(time.Hour).Format(time.RFC3339)}, Extra: map[string]any{"openai_excel_bps": true, "openai_excel_bps_auto_disable_on_403": true}}
}
func TestModelTraceCredentialReadOnly(t *testing.T) {
	for _, scenario := range []string{"valid", "expired", "missing", "canceled"} {
		t.Run(scenario, func(t *testing.T) {
			account := probeTestAccount()
			if scenario == "expired" {
				account.Credentials["expires_at"] = time.Now().Add(-time.Hour).Format(time.RFC3339)
			}
			if scenario == "missing" {
				delete(account.Credentials, "access_token")
			}
			before, _ := json.Marshal(account)
			upstream := &probeHTTP{status: 200, body: "data: {\"type\":\"response.completed\"}\n\n"}
			transport := &OpenAIProbeTransport{upstream: upstream}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if scenario == "canceled" {
				cancel()
			}
			_, err := transport.Call(ctx, account, "codex", "gpt-6-astra", "数字挑战")
			if scenario == "valid" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				require.Nil(t, upstream.request)
			}
			after, _ := json.Marshal(account)
			require.JSONEq(t, string(before), string(after))
		})
	}
}
func TestModelTraceRequestStateIsolation(t *testing.T) {
	for _, protocol := range []string{"codex", "bps"} {
		for _, status := range []int{200, 401, 403, 429, 500} {
			t.Run(protocol+http.StatusText(status), func(t *testing.T) {
				account := probeTestAccount()
				rawBefore, _ := json.Marshal(account)
				upstream := &probeHTTP{status: status, body: "data: {\"type\":\"response.output_text.delta\",\"delta\":\"1 2 3\"}\n\ndata: {\"type\":\"response.completed\",\"response\":{\"output\":[]}}\n\n"}
				transport := &OpenAIProbeTransport{upstream: upstream}
				reply, err := transport.Call(context.Background(), account, protocol, "gpt-6-astra", "数字挑战")
				if status == 200 {
					require.NoError(t, err)
					require.Equal(t, "1 2 3", reply.Text)
				} else {
					require.Error(t, err)
				}
				require.Equal(t, status, reply.Status)
				rawAfter, _ := json.Marshal(account)
				require.JSONEq(t, string(rawBefore), string(rawAfter))
				require.Equal(t, "Bearer access", upstream.request.Header.Get("Authorization"))
				if protocol == "bps" {
					require.Equal(t, "bps.openai.com", upstream.request.URL.Host)
				} else {
					require.Equal(t, "chatgpt.com", upstream.request.URL.Host)
				}
			})
		}
	}
}
func TestModelTraceStreamFailure(t *testing.T) {
	for _, body := range []string{"", "data: {\"type\":\"response.output_text.delta\",\"delta\":\"1 2\"}\n", "data: {\"type\":\"response.failed\"}\n"} {
		_, err := readProbeResponse(strings.NewReader(body))
		require.Error(t, err)
	}
}

func TestModelTraceTransportFailuresAndProxy(t *testing.T) {
	for _, protocol := range []string{"codex", "bps"} {
		for _, failure := range []string{"network", "timeout", "interrupted"} {
			t.Run(protocol+failure, func(t *testing.T) {
				account := probeTestAccount()
				account.Proxy = &Proxy{Protocol: "http", Host: "127.0.0.1", Port: 18080}
				before, _ := json.Marshal(account)
				upstream := &probeHTTP{status: 200, body: "data: {\"type\":\"response.output_text.delta\",\"delta\":\"1 2\"}\n\n"}
				if failure == "network" {
					upstream.err = io.ErrUnexpectedEOF
				}
				if failure == "timeout" {
					upstream.err = context.DeadlineExceeded
				}
				transport := NewOpenAIProbeTransport(upstream, nil)
				_, err := transport.Call(context.Background(), account, protocol, "gpt-6-astra", "数字挑战")
				require.Error(t, err)
				require.Equal(t, "http://127.0.0.1:18080", upstream.proxy)
				after, _ := json.Marshal(account)
				require.JSONEq(t, string(before), string(after))
			})
		}
	}
}

func TestModelTraceExplicitBPSDoesNotToggleAccount(t *testing.T) {
	account := probeTestAccount()
	account.Extra["openai_excel_bps"] = false
	account.Credentials["model_mapping"] = map[string]any{"alias": "gpt-6-astra"}
	before, _ := json.Marshal(account)
	upstream := &probeHTTP{status: 403}
	transport := NewOpenAIProbeTransport(upstream, nil)
	reply, err := transport.Call(context.Background(), account, "bps", "alias", "数字挑战")
	require.Error(t, err)
	require.Equal(t, "gpt-6-astra", reply.UpstreamModel)
	raw, err := io.ReadAll(upstream.request.Body)
	require.NoError(t, err)
	var body map[string]any
	require.NoError(t, json.Unmarshal(raw, &body))
	require.Equal(t, "gpt-6-astra", body["model"])
	after, _ := json.Marshal(account)
	require.JSONEq(t, string(before), string(after))
}
