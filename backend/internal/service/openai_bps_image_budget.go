package service

import (
	"sync"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/logger"
	"github.com/tidwall/gjson"
)

const (
	bpsImageMaxBodyBytes   = 64 << 20
	bpsImageBudgetBytes    = 512 << 20
	bpsImageBodyMultiplier = 8
	bpsImageMinBodyBytes   = 1 << 20
	bpsImageMaxRequests    = 32
)

// 仅实际 BPS 图片转发申请额度；直至转发返回才释放，不淘汰活动请求。
type bpsImageAdmissionBudget struct {
	mu       sync.Mutex
	bytes    int64
	requests int
}

func (b *bpsImageAdmissionBudget) acquire(bodyBytes int64, requestID string) (func(), bool) {
	if bodyBytes < bpsImageMinBodyBytes {
		bodyBytes = bpsImageMinBodyBytes
	}
	weight := bodyBytes * bpsImageBodyMultiplier
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.requests >= bpsImageMaxRequests || weight > bpsImageBudgetBytes-b.bytes {
		logger.LegacyPrintf("service.bps_image_budget", "rejected request_id=%s requested_bytes=%d reserved_bytes=%d requests=%d limit_bytes=%d", requestID, weight, b.bytes, b.requests, bpsImageBudgetBytes)
		return nil, false
	}
	b.bytes += weight
	b.requests++
	started := time.Now()
	logger.LegacyPrintf("service.bps_image_budget", "acquired request_id=%s weight_bytes=%d reserved_bytes=%d requests=%d", requestID, weight, b.bytes, b.requests)
	var once sync.Once
	return func() {
		once.Do(func() {
			b.mu.Lock()
			defer b.mu.Unlock()
			b.bytes -= weight
			b.requests--
			logger.LegacyPrintf("service.bps_image_budget", "released request_id=%s weight_bytes=%d reserved_bytes=%d requests=%d held_ms=%d", requestID, weight, b.bytes, b.requests, time.Since(started).Milliseconds())
		})
	}, true
}

// 只遍历输入内容，不解析工具参数中的字符串，也不记录图片数据。
func responsesImageCount(body []byte) int {
	var count func(gjson.Result) int
	count = func(value gjson.Result) int {
		n := 0
		if value.IsObject() {
			switch value.Get("type").String() {
			case "input_image", "image_url", "image":
				return 1
			}
		}
		if value.IsObject() || value.IsArray() {
			value.ForEach(func(_, child gjson.Result) bool { n += count(child); return true })
		}
		return n
	}
	return count(gjson.GetBytes(body, "input"))
}
