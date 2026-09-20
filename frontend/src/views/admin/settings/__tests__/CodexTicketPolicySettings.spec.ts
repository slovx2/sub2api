import { mount } from '@vue/test-utils'
import { describe, expect, it, vi } from 'vitest'
import CodexTicketPolicySettings from '../CodexTicketPolicySettings.vue'
import { validCodexTicketPolicy, type CodexTicketPolicy } from '@/utils/codexTicketPolicy'

vi.mock('vue-i18n', () => ({ useI18n: () => ({ t: (key: string) => key.split('.').at(-1) }) }))
const defaults: CodexTicketPolicy = { ttl_seconds: 3600, refresh_before_seconds: 600, max_consecutive_failures: 30, harvest_interval_seconds: 20 }

describe('CodexTicketPolicySettings', () => {
  it('renders lifetime, lead, interval and failure threshold', () => {
    const wrapper = mount(CodexTicketPolicySettings, { props: { modelValue: defaults } })
    expect(wrapper.findAll('input').map(input => input.element.value)).toEqual(['60', '10', '20', '30'])
    expect(wrapper.find('[id*="cooldown"]').exists()).toBe(false)
    expect(wrapper.find('[role="alert"]').exists()).toBe(false)
  })

  it('converts minutes to seconds, allows zero lead, and shows saved values', async () => {
    const wrapper = mount(CodexTicketPolicySettings, { props: { modelValue: defaults } })
    await wrapper.get('#codex-ticket-ttl_seconds').setValue('120')
    expect(wrapper.emitted('update:modelValue')?.at(-1)?.[0]).toEqual({ ...defaults, ttl_seconds: 7200 })
    await wrapper.get('#codex-ticket-refresh_before_seconds').setValue('0')
    expect(wrapper.emitted('update:modelValue')?.at(-1)?.[0]).toEqual({ ...defaults, refresh_before_seconds: 0 })
    await wrapper.get('#codex-ticket-harvest_interval_seconds').setValue('30')
    expect(wrapper.emitted('update:modelValue')?.at(-1)?.[0]).toEqual({ ...defaults, harvest_interval_seconds: 30 })
    await wrapper.setProps({ modelValue: { ttl_seconds: 7200, refresh_before_seconds: 0, max_consecutive_failures: 5, harvest_interval_seconds: 1800 } })
    expect(wrapper.findAll('input').map(input => input.element.value)).toEqual(['120', '0', '1800', '5'])
  })

  it('does not silently replace empty inputs with defaults', async () => {
    const wrapper = mount(CodexTicketPolicySettings, { props: { modelValue: defaults } })
    await wrapper.get('#codex-ticket-max_consecutive_failures').setValue('')
    const invalid = wrapper.emitted('update:modelValue')?.at(-1)?.[0] as CodexTicketPolicy
    expect(Number.isNaN(invalid.max_consecutive_failures)).toBe(true)
    await wrapper.setProps({ modelValue: invalid })
    expect(wrapper.get('[role="alert"]').text()).toBe('invalid')
    expect(validCodexTicketPolicy(invalid)).toBe(false)
  })

  it('uses the same integer and range rules as the API', () => {
    expect(validCodexTicketPolicy(defaults)).toBe(true)
    for (const change of [
      { ttl_seconds: 59 }, { ttl_seconds: 86401 }, { ttl_seconds: 60.1 },
      { refresh_before_seconds: -1 }, { refresh_before_seconds: 3600 },
      { max_consecutive_failures: 0 }, { max_consecutive_failures: 10001 }, { max_consecutive_failures: 1.5 },
      { harvest_interval_seconds: 0 }, { harvest_interval_seconds: 86401 }, { harvest_interval_seconds: 1.5 }
    ]) expect(validCodexTicketPolicy({ ...defaults, ...change })).toBe(false)
    expect(validCodexTicketPolicy({ ttl_seconds: 60, refresh_before_seconds: 0, max_consecutive_failures: 1, harvest_interval_seconds: 1 })).toBe(true)
    expect(validCodexTicketPolicy({ ttl_seconds: 86400, refresh_before_seconds: 86399, max_consecutive_failures: 10000, harvest_interval_seconds: 86400 })).toBe(true)
  })
})
