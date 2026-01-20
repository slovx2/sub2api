package payment

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"sort"
	"sync"
	"testing"
	"time"

	baseservice "github.com/Wei-Shaw/sub2api/internal/service"
)

type testKeys struct {
	merchantPublic        *rsa.PublicKey
	platformPrivate       *rsa.PrivateKey
	merchantPrivateBase64 string
	platformPublicBase64  string
}

func newTestKeys(t *testing.T) testKeys {
	t.Helper()

	merchantPrivate, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate merchant key: %v", err)
	}
	platformPrivate, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate platform key: %v", err)
	}

	merchantPrivateDER := x509.MarshalPKCS1PrivateKey(merchantPrivate)

	platformPublicDER, err := x509.MarshalPKIXPublicKey(&platformPrivate.PublicKey)
	if err != nil {
		t.Fatalf("marshal platform public key: %v", err)
	}

	return testKeys{
		merchantPublic:        &merchantPrivate.PublicKey,
		platformPrivate:       platformPrivate,
		merchantPrivateBase64: base64.StdEncoding.EncodeToString(merchantPrivateDER),
		platformPublicBase64:  base64.StdEncoding.EncodeToString(platformPublicDER),
	}
}

func signParams(t *testing.T, priv *rsa.PrivateKey, params map[string]string) string {
	t.Helper()

	content := buildSignContent(params)
	sum := sha256.Sum256([]byte(content))
	signature, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatalf("sign params: %v", err)
	}
	return base64.StdEncoding.EncodeToString(signature)
}

func verifySignature(pub *rsa.PublicKey, params map[string]string, sign string) error {
	if sign == "" {
		return errors.New("missing sign")
	}
	content := buildSignContent(params)
	signature, err := base64.StdEncoding.DecodeString(sign)
	if err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(content))
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], signature)
}

type memoryOrderRepo struct {
	mu     sync.Mutex
	orders map[int64]*Order
	byNo   map[string]*Order
	nextID int64
}

func newMemoryOrderRepo() *memoryOrderRepo {
	return &memoryOrderRepo{
		orders: make(map[int64]*Order),
		byNo:   make(map[string]*Order),
	}
}

func (r *memoryOrderRepo) Create(ctx context.Context, order *Order) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if order == nil {
		return errors.New("nil order")
	}
	if order.ID == 0 {
		r.nextID++
		order.ID = r.nextID
	}
	now := time.Now()
	order.CreatedAt = now
	order.UpdatedAt = now
	r.orders[order.ID] = order
	r.byNo[order.OrderNo] = order
	return nil
}

func (r *memoryOrderRepo) GetByID(ctx context.Context, id int64) (*Order, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	order, ok := r.orders[id]
	if !ok {
		return nil, ErrOrderNotFound
	}
	return order, nil
}

func (r *memoryOrderRepo) GetByOrderNo(ctx context.Context, orderNo string) (*Order, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	order, ok := r.byNo[orderNo]
	if !ok {
		return nil, ErrOrderNotFound
	}
	return order, nil
}

func (r *memoryOrderRepo) ListByUserID(ctx context.Context, userID int64, page, pageSize int) ([]*Order, int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}

	matched := make([]*Order, 0)
	for _, order := range r.orders {
		if order.UserID == userID {
			matched = append(matched, order)
		}
	}
	sort.Slice(matched, func(i, j int) bool {
		if matched[i].CreatedAt.Equal(matched[j].CreatedAt) {
			return matched[i].ID > matched[j].ID
		}
		return matched[i].CreatedAt.After(matched[j].CreatedAt)
	})

	total := int64(len(matched))
	start := (page - 1) * pageSize
	if start >= len(matched) {
		return []*Order{}, total, nil
	}
	end := start + pageSize
	if end > len(matched) {
		end = len(matched)
	}
	return matched[start:end], total, nil
}

func (r *memoryOrderRepo) UpdateAfterCreate(ctx context.Context, id int64, tradeNo, payType, payInfo string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	order, ok := r.orders[id]
	if !ok {
		return ErrOrderNotFound
	}
	order.TradeNo = tradeNo
	order.PayType = payType
	order.PayInfo = payInfo
	order.Status = StatusPaying
	order.UpdatedAt = time.Now()
	return nil
}

func (r *memoryOrderRepo) UpdateNotifyInfo(ctx context.Context, id int64, tradeNo, apiTradeNo, payType, payload string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	order, ok := r.orders[id]
	if !ok {
		return ErrOrderNotFound
	}
	if tradeNo != "" {
		order.TradeNo = tradeNo
	}
	if apiTradeNo != "" {
		order.APITradeNo = apiTradeNo
	}
	if payType != "" {
		order.PayType = payType
	}
	order.NotifyPayload = payload
	order.UpdatedAt = time.Now()
	return nil
}

func (r *memoryOrderRepo) MarkPaid(ctx context.Context, id int64, paidAt time.Time) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	order, ok := r.orders[id]
	if !ok {
		return false, ErrOrderNotFound
	}
	if order.Status != StatusCreated && order.Status != StatusPaying {
		return false, nil
	}
	order.Status = StatusPaid
	order.PaidAt = &paidAt
	order.UpdatedAt = time.Now()
	return true, nil
}

func (r *memoryOrderRepo) StartCrediting(ctx context.Context, id int64) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	order, ok := r.orders[id]
	if !ok {
		return false, ErrOrderNotFound
	}
	if order.Status != StatusPaid {
		return false, nil
	}
	order.Status = StatusCrediting
	order.UpdatedAt = time.Now()
	return true, nil
}

func (r *memoryOrderRepo) RevertCrediting(ctx context.Context, id int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	order, ok := r.orders[id]
	if !ok {
		return ErrOrderNotFound
	}
	if order.Status == StatusCrediting {
		order.Status = StatusPaid
		order.UpdatedAt = time.Now()
	}
	return nil
}

func (r *memoryOrderRepo) MarkCredited(ctx context.Context, id int64, creditedAt time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	order, ok := r.orders[id]
	if !ok {
		return ErrOrderNotFound
	}
	if order.Status != StatusCrediting {
		return nil
	}
	order.Status = StatusCredited
	order.CreditedAt = &creditedAt
	order.UpdatedAt = time.Now()
	return nil
}

func (r *memoryOrderRepo) MarkFailed(ctx context.Context, id int64, reason string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	order, ok := r.orders[id]
	if !ok {
		return ErrOrderNotFound
	}
	order.Status = StatusFailed
	order.LastError = reason
	order.UpdatedAt = time.Now()
	return nil
}

func (r *memoryOrderRepo) UpdateLastError(ctx context.Context, id int64, reason string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	order, ok := r.orders[id]
	if !ok {
		return ErrOrderNotFound
	}
	order.LastError = reason
	order.UpdatedAt = time.Now()
	return nil
}

type adminServiceStub struct {
	updateBalanceErr   error
	updateBalanceCalls int
	lastUserID         int64
	lastAmount         float64
	lastOperation      string
	lastNotes          string
}

func (s *adminServiceStub) ListUsers(ctx context.Context, page, pageSize int, filters baseservice.UserListFilters) ([]baseservice.User, int64, error) {
	return nil, 0, nil
}

func (s *adminServiceStub) GetUser(ctx context.Context, id int64) (*baseservice.User, error) {
	return nil, nil
}

func (s *adminServiceStub) CreateUser(ctx context.Context, input *baseservice.CreateUserInput) (*baseservice.User, error) {
	return nil, nil
}

func (s *adminServiceStub) UpdateUser(ctx context.Context, id int64, input *baseservice.UpdateUserInput) (*baseservice.User, error) {
	return nil, nil
}

func (s *adminServiceStub) DeleteUser(ctx context.Context, id int64) error {
	return nil
}

func (s *adminServiceStub) UpdateUserBalance(ctx context.Context, userID int64, balance float64, operation string, notes string) (*baseservice.User, error) {
	s.updateBalanceCalls++
	s.lastUserID = userID
	s.lastAmount = balance
	s.lastOperation = operation
	s.lastNotes = notes
	if s.updateBalanceErr != nil {
		return nil, s.updateBalanceErr
	}
	return &baseservice.User{ID: userID, Balance: balance}, nil
}

func (s *adminServiceStub) GetUserAPIKeys(ctx context.Context, userID int64, page, pageSize int) ([]baseservice.APIKey, int64, error) {
	return nil, 0, nil
}

func (s *adminServiceStub) GetUserUsageStats(ctx context.Context, userID int64, period string) (any, error) {
	return nil, nil
}

func (s *adminServiceStub) ListGroups(ctx context.Context, page, pageSize int, platform, status, search string, isExclusive *bool) ([]baseservice.Group, int64, error) {
	return nil, 0, nil
}

func (s *adminServiceStub) GetAllGroups(ctx context.Context) ([]baseservice.Group, error) {
	return nil, nil
}

func (s *adminServiceStub) GetAllGroupsByPlatform(ctx context.Context, platform string) ([]baseservice.Group, error) {
	return nil, nil
}

func (s *adminServiceStub) GetGroup(ctx context.Context, id int64) (*baseservice.Group, error) {
	return nil, nil
}

func (s *adminServiceStub) CreateGroup(ctx context.Context, input *baseservice.CreateGroupInput) (*baseservice.Group, error) {
	return nil, nil
}

func (s *adminServiceStub) UpdateGroup(ctx context.Context, id int64, input *baseservice.UpdateGroupInput) (*baseservice.Group, error) {
	return nil, nil
}

func (s *adminServiceStub) DeleteGroup(ctx context.Context, id int64) error {
	return nil
}

func (s *adminServiceStub) GetGroupAPIKeys(ctx context.Context, groupID int64, page, pageSize int) ([]baseservice.APIKey, int64, error) {
	return nil, 0, nil
}

func (s *adminServiceStub) ListAccounts(ctx context.Context, page, pageSize int, platform, accountType, status, search string) ([]baseservice.Account, int64, error) {
	return nil, 0, nil
}

func (s *adminServiceStub) GetAccount(ctx context.Context, id int64) (*baseservice.Account, error) {
	return nil, nil
}

func (s *adminServiceStub) GetAccountsByIDs(ctx context.Context, ids []int64) ([]*baseservice.Account, error) {
	return nil, nil
}

func (s *adminServiceStub) CreateAccount(ctx context.Context, input *baseservice.CreateAccountInput) (*baseservice.Account, error) {
	return nil, nil
}

func (s *adminServiceStub) UpdateAccount(ctx context.Context, id int64, input *baseservice.UpdateAccountInput) (*baseservice.Account, error) {
	return nil, nil
}

func (s *adminServiceStub) DeleteAccount(ctx context.Context, id int64) error {
	return nil
}

func (s *adminServiceStub) LookupAccountsByCredentialEmail(ctx context.Context, platform string, emails []string) ([]baseservice.Account, error) {
	return nil, nil
}

func (s *adminServiceStub) RefreshAccountCredentials(ctx context.Context, id int64) (*baseservice.Account, error) {
	return nil, nil
}

func (s *adminServiceStub) ClearAccountError(ctx context.Context, id int64) (*baseservice.Account, error) {
	return nil, nil
}

func (s *adminServiceStub) SetAccountError(ctx context.Context, id int64, errorMsg string) error {
	return nil
}

func (s *adminServiceStub) SetAccountSchedulable(ctx context.Context, id int64, schedulable bool) (*baseservice.Account, error) {
	return nil, nil
}

func (s *adminServiceStub) BulkUpdateAccounts(ctx context.Context, input *baseservice.BulkUpdateAccountsInput) (*baseservice.BulkUpdateAccountsResult, error) {
	return nil, nil
}

func (s *adminServiceStub) ListProxies(ctx context.Context, page, pageSize int, protocol, status, search string) ([]baseservice.Proxy, int64, error) {
	return nil, 0, nil
}

func (s *adminServiceStub) ListProxiesWithAccountCount(ctx context.Context, page, pageSize int, protocol, status, search string) ([]baseservice.ProxyWithAccountCount, int64, error) {
	return nil, 0, nil
}

func (s *adminServiceStub) GetAllProxies(ctx context.Context) ([]baseservice.Proxy, error) {
	return nil, nil
}

func (s *adminServiceStub) GetAllProxiesWithAccountCount(ctx context.Context) ([]baseservice.ProxyWithAccountCount, error) {
	return nil, nil
}

func (s *adminServiceStub) GetProxy(ctx context.Context, id int64) (*baseservice.Proxy, error) {
	return nil, nil
}

func (s *adminServiceStub) CreateProxy(ctx context.Context, input *baseservice.CreateProxyInput) (*baseservice.Proxy, error) {
	return nil, nil
}

func (s *adminServiceStub) UpdateProxy(ctx context.Context, id int64, input *baseservice.UpdateProxyInput) (*baseservice.Proxy, error) {
	return nil, nil
}

func (s *adminServiceStub) DeleteProxy(ctx context.Context, id int64) error {
	return nil
}

func (s *adminServiceStub) BatchDeleteProxies(ctx context.Context, ids []int64) (*baseservice.ProxyBatchDeleteResult, error) {
	return nil, nil
}

func (s *adminServiceStub) GetProxyAccounts(ctx context.Context, proxyID int64) ([]baseservice.ProxyAccountSummary, error) {
	return nil, nil
}

func (s *adminServiceStub) CheckProxyExists(ctx context.Context, host string, port int, username, password string) (bool, error) {
	return false, nil
}

func (s *adminServiceStub) TestProxy(ctx context.Context, id int64) (*baseservice.ProxyTestResult, error) {
	return nil, nil
}

func (s *adminServiceStub) ListRedeemCodes(ctx context.Context, page, pageSize int, codeType, status, search string) ([]baseservice.RedeemCode, int64, error) {
	return nil, 0, nil
}

func (s *adminServiceStub) GetRedeemCode(ctx context.Context, id int64) (*baseservice.RedeemCode, error) {
	return nil, nil
}

func (s *adminServiceStub) GenerateRedeemCodes(ctx context.Context, input *baseservice.GenerateRedeemCodesInput) ([]baseservice.RedeemCode, error) {
	return nil, nil
}

func (s *adminServiceStub) DeleteRedeemCode(ctx context.Context, id int64) error {
	return nil
}

func (s *adminServiceStub) BatchDeleteRedeemCodes(ctx context.Context, ids []int64) (int64, error) {
	return 0, nil
}

func (s *adminServiceStub) ExpireRedeemCode(ctx context.Context, id int64) (*baseservice.RedeemCode, error) {
	return nil, nil
}
