export default {
    history: '最近 24 小时探测历史', historyHint: '展示当次预期与判定；修改预期不会改写历史。', historyExpected: '当次预期',
    protocol: '协议', allProtocols: '全部协议', filter: '筛选 / 刷新', time: '完成时间', result: '判定结果',
    noHistory: '最近 24 小时暂无探测记录', historyError: '历史记录加载失败', loadMore: '加载更多',
    streak: '连续匹配 {duration}', streakUnderMinute: '连续匹配不足 1 分钟', days: '{n} 天', hours: '{n} 小时', minutes: '{n} 分钟',
    description: '定时识别 OpenAI OAuth 账号实际返回的模型。探测结果不会修改账号状态。',
    enabled: '启用探测', all: '全部账号（自动包含新增账号）', selected: '手动选择', selectAll: '全选当前账号', clear: '清空', search: '搜索账号',
    interval: '间隔（分钟，最小 10）', concurrency: '账号并发数', request: '请求模型', expected: '预期模型（留空跟随请求模型）', add: '添加模型', remove: '移除',
    unknownModel: '预期模型尚未收录，无法识别为该模型。', bank: '评分仅在指纹库候选范围内比较；未收录模型也可能被归入现有候选。',
    save: '保存探测设置', run: '立即探测', saved: '探测设置已保存', queued: '已提交 {accepted} 个账号，{running} 个运行中或已排队，{unavailable} 个不可执行。',
    error: '操作失败', loading: '加载中…', dirty: '请先保存配置再立即探测。', disabled: '已停用', running: '探测中', matched: '匹配', mismatched: '不匹配',
    pending: '待探测', uncertain: '无法确定', failed: '无法判定', actual: '实际请求', retry: '重试', empty: '没有符合条件的账号', enabledProtocol: '启用 {protocol}',
}
