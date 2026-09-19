import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import CodexTicketManagementDialog from '../CodexTicketManagementDialog.vue'

const mocks = vi.hoisted(() => ({ overview: vi.fn(), logs: vi.fn() }))
vi.mock('@/api/admin/codexTickets', () => ({ getCodexTicketOverview: mocks.overview, getCodexTicketLogs: mocks.logs }))
vi.mock('vue-i18n', () => ({ useI18n: () => ({ t: (key: string) => key.split('.').at(-1) }) }))

describe('CodexTicketManagementDialog', () => {
  let wrapper: VueWrapper | undefined

  beforeEach(() => {
    vi.clearAllMocks()
    mocks.overview.mockResolvedValue({ enabled: true, accounts: 0, valid_tickets: 0, problem_accounts: 0, total: 0, items: [] })
    mocks.logs.mockResolvedValue({ total: 0, summary: { attempts: 0, success: 0, failure: 0, injection_missing: 0 }, items: [] })
    wrapper = mount(CodexTicketManagementDialog, {
      attachTo: document.body,
      global: { stubs: { teleport: true, transition: true, Icon: true } }
    })
  })

  afterEach(() => {
    wrapper?.unmount()
    document.body.innerHTML = ''
    vi.useRealTimers()
  })

  it('shows only the entry button until opened, then puts both sections in one dialog', async () => {
    await flushPromises()
    expect(wrapper!.find('[role="dialog"]').exists()).toBe(false)
    expect(mocks.logs).not.toHaveBeenCalled()
    expect(mocks.overview).not.toHaveBeenCalled()
    await wrapper!.get('[data-testid="open-ticket-management"]').trigger('click')
    await flushPromises()
    const dialog = wrapper!.get('[role="dialog"]')
    expect(dialog.text()).toContain('overview')
    expect(dialog.text()).toContain('diagnostics')
    expect(dialog.find('.modal-content').classes()).toContain('xl:max-w-6xl')
    expect(mocks.logs).toHaveBeenCalledTimes(1)
    await wrapper!.get('[data-testid="close-ticket-management"]').trigger('click')
    expect(wrapper!.find('[role="dialog"]').exists()).toBe(false)
  })

  it('cancels requests and auto refresh on Escape, and reloads on reopening', async () => {
    vi.useFakeTimers()
    const trigger = wrapper!.get('[data-testid="open-ticket-management"]')
    ;(trigger.element as HTMLButtonElement).focus()
    await trigger.trigger('click')
    await flushPromises()
    await wrapper!.get('input[type="checkbox"]').setValue(true)
    const signal = mocks.logs.mock.calls[0]![3] as AbortSignal
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }))
    await flushPromises()
    expect(signal.aborted).toBe(true)
    expect(document.activeElement).toBe(trigger.element)
    expect(wrapper!.find('[role="dialog"]').exists()).toBe(false)
    await vi.advanceTimersByTimeAsync(30000)
    expect(mocks.logs).toHaveBeenCalledTimes(1)
    await trigger.trigger('click')
    await flushPromises()
    expect(mocks.logs).toHaveBeenCalledTimes(2)
    expect((wrapper!.get('input[type="checkbox"]').element as HTMLInputElement).checked).toBe(false)
  })

  it('closes when clicking the backdrop', async () => {
    await wrapper!.get('[data-testid="open-ticket-management"]').trigger('click')
    await flushPromises()
    await wrapper!.get('[role="dialog"]').trigger('click')
    expect(wrapper!.find('[role="dialog"]').exists()).toBe(false)
  })
})
