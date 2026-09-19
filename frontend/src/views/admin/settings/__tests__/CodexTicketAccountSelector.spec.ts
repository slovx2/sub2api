import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import CodexTicketAccountSelector from '../CodexTicketAccountSelector.vue'

const mocks = vi.hoisted(() => ({ list: vi.fn() }))
vi.mock('@/api/admin/accounts', () => ({ list: mocks.list }))
vi.mock('vue-i18n', () => ({ useI18n: () => ({ t: (key: string) => key }) }))

const account = (id: number, extra = {}) => ({ id, name: `account-${id}`, platform: 'openai', type: 'oauth', status: 'active', ...extra })

describe('CodexTicketAccountSelector', () => {
  beforeEach(() => {
    mocks.list.mockReset()
    mocks.list.mockResolvedValue({ items: [account(363)], total: 1 })
    vi.spyOn(window, 'confirm').mockReturnValue(true)
  })
  afterEach(() => vi.restoreAllMocks())

  it('shows all-accounts warning and name/ID, without changing stored values on load', async () => {
    const wrapper = mount(CodexTicketAccountSelector, { props: { modelValue: [] } })
    await flushPromises()
    expect(wrapper.text()).toContain('codexTicketAccountsAll')
    expect(wrapper.text()).toContain('account-363 (#363)')
    expect(wrapper.emitted('update:modelValue')).toBeUndefined()
    wrapper.unmount()
  })

  it('keeps selections across pagination and search', async () => {
    mocks.list.mockResolvedValueOnce({ items: [account(363)], total: 21 })
    const wrapper = mount(CodexTicketAccountSelector, { props: { modelValue: [] } })
    await flushPromises()
    await wrapper.get('[data-account-id="363"]').setValue(true)
    expect(wrapper.emitted('update:modelValue')?.[0]).toEqual([[363]])
    await wrapper.setProps({ modelValue: [363] })
    mocks.list.mockResolvedValueOnce({ items: [account(42)], total: 21 })
    await wrapper.get('[data-testid="ticket-accounts-next"]').trigger('click')
    await flushPromises()
    expect(mocks.list.mock.calls.at(-1)?.[0]).toBe(2)
    await wrapper.get('[data-account-id="42"]').setValue(true)
    expect(wrapper.emitted('update:modelValue')?.at(-1)).toEqual([[42, 363]])
    await wrapper.setProps({ modelValue: [42, 363] })
    await wrapper.get('input:not([type="checkbox"])').setValue('missing')
    mocks.list.mockResolvedValueOnce({ items: [], total: 0 })
    await wrapper.get('input:not([type="checkbox"])').trigger('keydown.enter')
    await flushPromises()
    expect(mocks.list.mock.calls.at(-1)?.[0]).toBe(1)
    expect(mocks.list.mock.calls.at(-1)?.[2].search).toBe('missing')
    expect(wrapper.findAll('[data-selected-id]')).toHaveLength(2)
    wrapper.unmount()
  })

  it('retains saved deleted IDs and failures never change the scope', async () => {
    mocks.list.mockRejectedValueOnce(new Error('offline'))
    const wrapper = mount(CodexTicketAccountSelector, { props: { modelValue: [99999] } })
    await flushPromises()
    expect(wrapper.text()).toContain('#99999')
    expect(wrapper.find('[role="alert"]').exists()).toBe(true)
    expect(wrapper.emitted('update:modelValue')).toBeUndefined()
    vi.mocked(window.confirm).mockReturnValue(false)
    await wrapper.get('[data-selected-id="99999"]').trigger('click')
    expect(wrapper.emitted('update:modelValue')).toBeUndefined()
    vi.mocked(window.confirm).mockReturnValue(true)
    await wrapper.get('[data-testid="clear-ticket-accounts"]').trigger('click')
    expect(wrapper.emitted('update:modelValue')).toEqual([[[]]])
    wrapper.unmount()
  })

  it('excludes API keys, shadows and inactive accounts; accepts setup-token accounts', async () => {
    mocks.list.mockResolvedValueOnce({ items: [account(1, { type: 'apikey' }), account(2, { parent_account_id: 3 }), account(3, { status: 'disabled' }), account(4, { type: 'setup-token' })], total: 4 })
    const wrapper = mount(CodexTicketAccountSelector, { props: { modelValue: [] } })
    await flushPromises()
    for (const id of [1, 2, 3]) expect(wrapper.get(`[data-account-id="${id}"]`).attributes('disabled')).toBeDefined()
    expect(wrapper.get('[data-account-id="4"]').attributes('disabled')).toBeUndefined()
    wrapper.unmount()
  })
})
