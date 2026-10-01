import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createI18n } from 'vue-i18n'
import zh from '@/i18n/locales/zh/modeltrace'
import ModelTraceBadge from '../ModelTraceBadge.vue'
import ModelTraceSettings from '../ModelTraceSettings.vue'
import HelpTooltip from '@/components/common/HelpTooltip.vue'
import type { ModelTraceSummary } from '@/api/admin/modeltrace'

const api = vi.hoisted(() => ({ get: vi.fn(), save: vi.fn(), run: vi.fn(), success: vi.fn(), error: vi.fn() }))
vi.mock('@/api/admin/modeltrace', () => ({ getModelTraceSettings: api.get, saveModelTraceSettings: api.save, runModelTrace: api.run }))
vi.mock('@/stores', () => ({ useAppStore: () => ({ showSuccess: api.success, showError: api.error }) }))
const i18n = () => createI18n({ legacy: false, locale: 'zh', messages: { zh: { modeltrace: Object.fromEntries(Object.entries(zh).map(([key, value]) => [key, () => value])) } } })
const summary = (): ModelTraceSummary => ({ enabled: true, running: false, matched: 1, mismatched: 0, details: [
  { protocol: 'codex', model: 'requested', expected_model: 'actual', prediction: 'actual', probability: 0.90001, status: 'success', verdict: 'matched', finished_at: '2026-10-01T01:00:00Z', bank_version: 'bank' },
  { protocol: 'bps', model: 'requested', expected_model: 'actual', prediction: 'other', probability: 0.9, status: 'success', verdict: 'unknown', finished_at: '2026-10-01T01:00:00Z', bank_version: 'bank' },
] })
afterEach(() => { document.body.innerHTML = '' })
beforeEach(() => { vi.clearAllMocks() })
describe('ModelTrace 摘要', () => {
  it('公共 tooltip 的按钮先聚焦再点击时保持打开', async () => {
    const wrapper = mount(HelpTooltip, { props: { trigger: 'click', content: '详情' }, slots: { trigger: '<button>查看</button>' }, attachTo: document.body })
    const button = wrapper.get('button')
    await button.trigger('focusin')
    await button.trigger('click')
    expect((document.querySelector('[role="tooltip"]') as HTMLElement).style.display).not.toBe('none')
    await button.trigger('click')
    expect((document.querySelector('[role="tooltip"]') as HTMLElement).style.display).toBe('none')
    wrapper.unmount()
  })
  it('自身处理悬浮、聚焦和失焦，焦点后的点击不会关闭详情', async () => {
    const wrapper = mount(ModelTraceBadge, { props: { summary: summary() }, attachTo: document.body, global: { plugins: [i18n()] } })
    const button = wrapper.get('button')
    const tooltip = document.querySelector('[role="tooltip"]') as HTMLElement
    await button.trigger('mouseenter')
    expect(tooltip.style.display).not.toBe('none')
    await button.trigger('mouseleave')
    expect(tooltip.style.display).toBe('none')
    await button.trigger('focusin')
    await button.trigger('click')
    await button.trigger('mouseleave')
    expect(tooltip.style.display).not.toBe('none')
    expect(button.attributes('aria-describedby')).toBe(tooltip.id)
    await button.trigger('focusout')
    expect(tooltip.style.display).toBe('none')
    wrapper.unmount()
  })
  it('仅外显匹配计数，键盘聚焦显示详情，90% 仍显示概率', async () => {
    const wrapper = mount(ModelTraceBadge, { props: { summary: summary() }, attachTo: document.body, global: { plugins: [i18n()] } })
    const button = wrapper.get('button')
    expect(button.text()).toBe('匹配 1·不匹配 0')
    expect(button.text()).not.toContain('requested')
    await button.trigger('focusin')
    await flushPromises()
    const tooltip = document.querySelector('[role="tooltip"]')!
    expect((tooltip as HTMLElement).style.display).not.toBe('none')
    expect(tooltip.textContent).toContain('other 90.0%')
    expect(tooltip.textContent).not.toContain('90.001')
    await button.trigger('keydown', { key: 'Escape' })
    expect((tooltip as HTMLElement).style.display).toBe('none')
    wrapper.unmount()
  })
  it('显示失败和停用，不添加外层状态', async () => {
    const value = summary(); value.enabled = false; value.matched = 0
    value.details[0].status = 'error'; value.details[0].error = 'HTTP 403'; value.details[0].verdict = 'unknown'
    const wrapper = mount(ModelTraceBadge, { props: { summary: value }, attachTo: document.body, global: { plugins: [i18n()] } })
    await wrapper.get('button').trigger('focusin')
    expect(document.querySelector('[role="tooltip"]')!.textContent).toContain('HTTP 403')
    expect(document.querySelector('[role="tooltip"]')!.textContent).toContain('已停用')
    expect(wrapper.get('button').text()).toBe('匹配 0·不匹配 0')
    wrapper.unmount()
  })
})
describe('ModelTrace 设置', () => {
  it('删除首行保留后续输入框的 DOM 身份，编辑模型名不会替换输入框', async () => {
    api.get.mockResolvedValue({ config: { enabled: true, account_mode: 'all', account_ids: [], targets: [
      { protocol: 'codex', model: 'first', expected_model: '' },
      { protocol: 'codex', model: 'second', expected_model: '' },
    ], interval_minutes: 30, concurrency: 5 }, accounts: [], candidates: [] })
    const wrapper = mount(ModelTraceSettings, { global: { plugins: [i18n()] } })
    await flushPromises()
    const second = wrapper.findAll('input[maxlength="256"]')[2]
    const originalElement = second.element
    await second.setValue('edited')
    expect(wrapper.findAll('input[maxlength="256"]')[2].element).toBe(originalElement)
    await wrapper.findAll('button').find(b => b.text() === '移除')!.trigger('click')
    const remaining = wrapper.findAll('input[maxlength="256"]')[0]
    expect(remaining.element).toBe(originalElement)
    expect((remaining.element as HTMLInputElement).value).toBe('edited')
    wrapper.unmount()
  })
  it('保存全量选择和自填预期模型，脏配置禁止立即探测', async () => {
    api.get.mockResolvedValue({ config: { enabled: true, account_mode: 'all', account_ids: [], targets: [{ protocol: 'codex', model: 'requested', expected_model: '' }], interval_minutes: 30, concurrency: 5 }, accounts: [{ id: 1, name: 'test' }], candidates: ['actual'], bank_version: 'bank' })
    api.save.mockImplementation(async value => JSON.parse(JSON.stringify(value)))
    api.run.mockResolvedValue({ accepted: 1, running: 0, unavailable: 0 })
    const wrapper = mount(ModelTraceSettings, { global: { plugins: [i18n()] } })
    await flushPromises()
    const buttons = () => wrapper.findAll('button')
    const run = () => buttons().find(b => b.text() === '立即探测')!
    expect(run().attributes('disabled')).toBeUndefined()
    const modelInputs = wrapper.findAll('input[maxlength="256"]')
    await modelInputs[1].setValue('actual')
    expect(run().attributes('disabled')).toBeDefined()
    await buttons().find(b => b.text() === '保存探测设置')!.trigger('click')
    await flushPromises()
    expect(api.save).toHaveBeenCalledWith(expect.objectContaining({ account_mode: 'all', targets: [{ protocol: 'codex', model: 'requested', expected_model: 'actual' }] }))
    expect(run().attributes('disabled')).toBeUndefined()
    await run().trigger('click'); await flushPromises()
    expect(api.run).toHaveBeenCalledTimes(1)
    wrapper.unmount()
  })
})
