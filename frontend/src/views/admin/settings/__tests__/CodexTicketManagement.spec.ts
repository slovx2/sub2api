import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import CodexTicketManagement from '../CodexTicketManagement.vue'

const mocks = vi.hoisted(() => ({ overview: vi.fn(), logs: vi.fn() }))
vi.mock('@/api/admin/codexTickets', () => ({ getCodexTicketOverview: mocks.overview, getCodexTicketLogs: mocks.logs }))
vi.mock('vue-i18n', () => ({ useI18n: () => ({ t: (key: string) => key.split('.').at(-1) }) }))

describe('CodexTicketManagement', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mocks.overview.mockResolvedValue({ enabled: true, accounts: 1, valid_tickets: 2, problem_accounts: 0, total: 2, items: [
      { account_id: 7, account_name: 'ticket-account', model: 'gpt-6-astra', length: 332, ready: true, remaining_seconds: 1800, expires_at: '2026-09-19T14:00:00Z' },
      { account_id: 7, account_name: 'ticket-account', model: 'gpt-5.6-sol', length: 292, ready: true, remaining_seconds: 1800 }
    ] })
    mocks.logs.mockResolvedValue({ total: 21, summary: { attempts: 21, success: 20, failure: 1, injection_missing: 0 }, items: [
      { id: 2, account_id: 7, account_name: 'ticket-account', model: 'gpt-6-astra', kind: 'harvest', length: 332, http_status: 200, success: true, reason: 'accepted', created_at: '2026-09-19T13:00:00Z' },
      { id: 1, account_id: 7, account_name: 'ticket-account', model: 'gpt-6-astra', kind: 'harvest', length: 0, http_status: 429, success: false, reason: 'http_error', created_at: '2026-09-19T12:00:00Z' }
    ] })
  })
  afterEach(() => { vi.useRealTimers() })

  it('renders both accepted lengths and success/failure logs', async () => {
    const wrapper = mount(CodexTicketManagement)
    await flushPromises()
    expect(wrapper.text()).toContain('332')
    expect(wrapper.text()).toContain('292')
    const rows = wrapper.findAll('tbody tr')
    expect(rows).toHaveLength(2)
    expect(rows[0]!.text()).toContain('success')
    expect(rows[0]!.text()).toContain('200')
    expect(rows[1]!.text()).toContain('failure')
    expect(rows[1]!.text()).toContain('429')
    expect(wrapper.text()).toContain('ticket-account (#7)')
    wrapper.unmount()
  })

  it('paginates and resets to page one when filtering', async () => {
    const wrapper = mount(CodexTicketManagement)
    await flushPromises()
    await wrapper.get('[data-testid="ticket-logs-next"]').trigger('click')
    await flushPromises()
    expect(mocks.logs.mock.calls.at(-1)?.[0]).toBe(2)
    await wrapper.get('input[type="number"]').setValue('7')
    await wrapper.get('select').setValue('success')
    await flushPromises()
    expect(mocks.logs.mock.calls.at(-1)?.slice(0, 3)).toEqual([1, 7, 'success'])
    expect(wrapper.get('[data-testid="ticket-logs-prev"]').attributes('disabled')).toBeDefined()
    wrapper.unmount()
  })

  it('shows load errors without claiming a successful empty state', async () => {
    mocks.logs.mockRejectedValueOnce(new Error('offline'))
    const wrapper = mount(CodexTicketManagement)
    await flushPromises()
    expect(wrapper.get('[role="alert"]').text()).toBe('loadError')
    expect(wrapper.text()).not.toContain('noLogs')
    wrapper.unmount()
  })

  it('automatically refreshes only when selected and cleans up on unmount', async () => {
    vi.useFakeTimers()
    const wrapper = mount(CodexTicketManagement)
    await flushPromises()
    await vi.advanceTimersByTimeAsync(15000)
    expect(mocks.logs).toHaveBeenCalledTimes(1)
    await wrapper.get('input[type="checkbox"]').setValue(true)
    await vi.advanceTimersByTimeAsync(15000)
    await flushPromises()
    expect(mocks.logs).toHaveBeenCalledTimes(2)
    const signal = mocks.logs.mock.calls.at(-1)?.[3] as AbortSignal
    wrapper.unmount()
    expect(signal.aborted).toBe(true)
    await vi.advanceTimersByTimeAsync(30000)
    expect(mocks.logs).toHaveBeenCalledTimes(2)
  })
})
