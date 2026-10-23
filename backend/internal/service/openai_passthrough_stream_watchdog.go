package service

import (
	"context"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// openAIPassthroughDisconnectDrainTimeout 客户端断开且已有输出时，继续排空上游以收集 usage 的最长时间。
// 超过后放弃 usage、关闭上游，避免无人接收的长流（实测可达 800s+）持续占用请求体内存。
const openAIPassthroughDisconnectDrainTimeout = 120 * time.Second

type openAIPassthroughStreamCutReason string

const (
	openAIPassthroughStreamCutNone         openAIPassthroughStreamCutReason = ""
	openAIPassthroughStreamCutIdleTimeout  openAIPassthroughStreamCutReason = "upstream_idle_timeout"
	openAIPassthroughStreamCutClientGone   openAIPassthroughStreamCutReason = "client_gone_before_output"
	openAIPassthroughStreamCutDrainTimeout openAIPassthroughStreamCutReason = "client_gone_drain_timeout"
)

// openAIPassthroughStreamWatchdog 透传流式读取的看门狗。
//
// 透传路径用阻塞的 bufio.Scanner 直接读上游，上游 context 又与客户端脱钩
// （detachUpstreamContext），因此上游挂起或客户端早已断开时读取会一直阻塞。
// 看门狗在以下情况关闭上游 body，让 Scan 立即返回错误：
//   - 上游连续 idleTimeout 没有数据（idleTimeout<=0 时不启用）；
//   - 客户端断开时尚未向客户端输出内容；
//   - 客户端断开时已有输出，但排空超过 drainTimeout。
type openAIPassthroughStreamWatchdog struct {
	body          io.Closer
	idleTimeout   time.Duration
	drainTimeout  time.Duration
	idleTimer     *time.Timer
	outputStarted atomic.Bool
	reason        atomic.Value // openAIPassthroughStreamCutReason
	fireOnce      sync.Once
	stopOnce      sync.Once
	stopCh        chan struct{}
}

func startOpenAIPassthroughStreamWatchdog(
	clientCtx context.Context,
	body io.Closer,
	idleTimeout time.Duration,
	drainTimeout time.Duration,
) *openAIPassthroughStreamWatchdog {
	w := &openAIPassthroughStreamWatchdog{
		body:         body,
		idleTimeout:  idleTimeout,
		drainTimeout: drainTimeout,
		stopCh:       make(chan struct{}),
	}
	if idleTimeout > 0 {
		w.idleTimer = time.AfterFunc(idleTimeout, func() { w.fire(openAIPassthroughStreamCutIdleTimeout) })
	}
	if clientCtx != nil && clientCtx.Done() != nil {
		go w.watchClient(clientCtx)
	}
	return w
}

func (w *openAIPassthroughStreamWatchdog) watchClient(clientCtx context.Context) {
	select {
	case <-clientCtx.Done():
	case <-w.stopCh:
		return
	}
	if !w.outputStarted.Load() {
		w.fire(openAIPassthroughStreamCutClientGone)
		return
	}
	if w.drainTimeout <= 0 {
		return
	}
	timer := time.NewTimer(w.drainTimeout)
	defer timer.Stop()
	select {
	case <-timer.C:
		w.fire(openAIPassthroughStreamCutDrainTimeout)
	case <-w.stopCh:
	}
}

// Touch 每读到一行上游数据调用一次，重置空闲计时。
func (w *openAIPassthroughStreamWatchdog) Touch() {
	if w.idleTimer != nil {
		w.idleTimer.Reset(w.idleTimeout)
	}
}

// MarkOutputStarted 已向客户端写出首个内容后调用。
func (w *openAIPassthroughStreamWatchdog) MarkOutputStarted() {
	w.outputStarted.Store(true)
}

// Reason 返回看门狗关闭上游的原因；未触发时为空。
func (w *openAIPassthroughStreamWatchdog) Reason() openAIPassthroughStreamCutReason {
	if v, ok := w.reason.Load().(openAIPassthroughStreamCutReason); ok {
		return v
	}
	return openAIPassthroughStreamCutNone
}

// Stop 读取结束后调用，释放计时器和监听 goroutine；不关闭 body。
func (w *openAIPassthroughStreamWatchdog) Stop() {
	w.stopOnce.Do(func() {
		close(w.stopCh)
		if w.idleTimer != nil {
			w.idleTimer.Stop()
		}
	})
}

func (w *openAIPassthroughStreamWatchdog) fire(reason openAIPassthroughStreamCutReason) {
	select {
	case <-w.stopCh:
		return
	default:
	}
	w.fireOnce.Do(func() {
		w.reason.Store(reason)
		_ = w.body.Close()
	})
}
