package service

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/logger"
	"go.uber.org/zap"
)

// 只保存诊断元数据，禁止存入 token、代理地址和票据正文。
type CodexTicketEvent struct {
	ID          int64     `json:"id"`
	AccountID   int64     `json:"account_id"`
	AccountName string    `json:"account_name"`
	Model       string    `json:"model"`
	Kind        string    `json:"kind"`
	Length      int       `json:"length"`
	HTTPStatus  int       `json:"http_status"`
	Success     bool      `json:"success"`
	Reason      string    `json:"reason"`
	CreatedAt   time.Time `json:"created_at"`
}

type CodexTicketLogFilter struct {
	Page      int
	PageSize  int
	AccountID int64
	Result    string
}

type CodexTicketLogSummary struct {
	Attempts         int64 `json:"attempts"`
	Success          int64 `json:"success"`
	Failure          int64 `json:"failure"`
	InjectionMissing int64 `json:"injection_missing"`
}

type CodexTicketLogPage struct {
	Items   []CodexTicketEvent    `json:"items"`
	Total   int64                 `json:"total"`
	Summary CodexTicketLogSummary `json:"summary"`
}

type CodexTicketLogRepository interface {
	Create(context.Context, *CodexTicketEvent) error
	List(context.Context, CodexTicketLogFilter) (*CodexTicketLogPage, error)
}

type CodexTicketOverviewItem struct {
	AccountID   int64  `json:"account_id"`
	AccountName string `json:"account_name"`
	OpenAICodexTicketStatus
}

type CodexTicketOverview struct {
	Enabled         bool                      `json:"enabled"`
	Accounts        int                       `json:"accounts"`
	ValidTickets    int                       `json:"valid_tickets"`
	ProblemAccounts int                       `json:"problem_accounts"`
	Total           int                       `json:"total"`
	Items           []CodexTicketOverviewItem `json:"items"`
}

func (s *OpenAIGatewayService) recordCodexTicketEvent(ctx context.Context, event *CodexTicketEvent) {
	if s.codexTicketLogRepo == nil {
		return
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now()
	}
	// 请求取消仍须记录结果，但不能无限阻塞转发或关闭流程。
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	if err := s.codexTicketLogRepo.Create(writeCtx, event); err != nil {
		logger.L().Warn("codex ticket diagnostic write failed", zap.Int64("account_id", event.AccountID), zap.Error(err))
	}
}

func (s *OpenAIGatewayService) ListCodexTicketLogs(ctx context.Context, filter CodexTicketLogFilter) (*CodexTicketLogPage, error) {
	if s.codexTicketLogRepo == nil {
		return nil, errors.New("打票日志存储未初始化")
	}
	return s.codexTicketLogRepo.List(ctx, filter)
}

// 总览复用原账号范围及票据校验，并优先读取本实例的最新缓存。
func (s *OpenAIGatewayService) CodexTicketOverview(ctx context.Context, page, pageSize int, problemsOnly bool) (*CodexTicketOverview, error) {
	cfg := s.openAICodexTicketConfig()
	cfg.Enabled = s.openAICodexTicketEnabledContext(ctx)
	cfg.AccountIDs, _ = s.codexTicketAccountScope(ctx)
	out := &CodexTicketOverview{Enabled: cfg.Enabled, Items: []CodexTicketOverviewItem{}}
	if !cfg.Enabled {
		return out, nil
	}
	accounts, err := s.accountRepo.ListByPlatform(ctx, PlatformOpenAI)
	if err != nil {
		return nil, err
	}
	sort.Slice(accounts, func(i, j int) bool { return accounts[i].ID < accounts[j].ID })
	now := time.Now()
	items := []CodexTicketOverviewItem{}
	for i := range accounts {
		account := &accounts[i]
		if account.Status != StatusActive || !isOpenAICodexTicketAccount(account) || !codexTicketAccountSelected(cfg.AccountIDs, account.ID) {
			continue
		}
		out.Accounts++
		problem := false
		for _, model := range cfg.Models {
			ticket := s.lookupOpenAICodexTicket(account, model)
			status := OpenAICodexTicketStatus{Model: model}
			if ticket.valid(now, cfg.TargetLength) {
				status.Ready, status.Length = true, ticket.Length
				status.RemainingSeconds = int64(ticket.ExpiresAt.Sub(now) / time.Second)
				expires := ticket.ExpiresAt
				status.ExpiresAt = &expires
				out.ValidTickets++
			} else {
				problem = true
			}
			status.Blocked = cfg.FailClosed && !status.Ready
			if !problemsOnly || !status.Ready {
				items = append(items, CodexTicketOverviewItem{AccountID: account.ID, AccountName: account.Name, OpenAICodexTicketStatus: status})
			}
		}
		if problem {
			out.ProblemAccounts++
		}
	}
	out.Total = len(items)
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	start := (page - 1) * pageSize
	if start >= 0 && start < len(items) {
		out.Items = items[start:min(start+pageSize, len(items))]
	}
	return out, nil
}
