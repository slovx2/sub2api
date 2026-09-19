import { mount } from '@vue/test-utils'
import { describe, expect, it, vi } from 'vitest'
import CodexTicketPolicySettings from '../CodexTicketPolicySettings.vue'
import { validCodexTicketPolicy, type CodexTicketPolicy } from '@/utils/codexTicketPolicy'

vi.mock('vue-i18n', () => ({ useI18n: () => ({ t: (key: string) => key.split('.').at(-1) }) }))
const defaults: CodexTicketPolicy = { ttl_seconds: 3600, refresh_before_seconds: 600, max_attempts: 3, failure_cooldown_seconds: 3600 }

describe('CodexTicketPolicySettings', () => {
  it('renders four settings with minute units and no interval', () => {
    const wrapper = mount(CodexTicketPolicySettings, { props: { modelValue: defaults } })
    expect(wrapper.findAll('input').map(input => input.element.value)).toEqual(['60', '10', '3', '60'])
    expect(wrapper.find('[id*="interval"]').exists()).toBe(false)
    expect(wrapper.find('[role="alert"]').exists()).toBe(false)
  })

  it('converts minutes to seconds, allows zero lead, and shows saved values', async () => {
    const wrapper = mount(CodexTicketPolicySettings, { props: { modelValue: defaults } })
    await wrapper.get('#codex-ticket-ttl_seconds').setValue('120')
    expect(wrapper.emitted('update:modelValue')?.at(-1)?.[0]).toEqual({ ...defaults, ttl_seconds: 7200 })
    await wrapper.get('#codex-ticket-refresh_before_seconds').setValue('0')
    expect(wrapper.emitted('update:modelValue')?.at(-1)?.[0]).toEqual({ ...defaults, refresh_before_seconds: 0 })
    await wrapper.get('#codex-ticket-failure_cooldown_seconds').setValue('30')
    expect(wrapper.emitted('update:modelValue')?.at(-1)?.[0]).toEqual({ ...defaults, failure_cooldown_seconds: 1800 })
    await wrapper.setProps({ modelValue: { ttl_seconds: 7200, refresh_before_seconds: 0, max_attempts: 5, failure_cooldown_seconds: 1800 } })
    expect(wrapper.findAll('input').map(input => input.element.value)).toEqual(['120', '0', '5', '30'])
  })

  it('does not silently replace empty inputs with defaults', async () => {
    const wrapper = mount(CodexTicketPolicySettings, { props: { modelValue: defaults } })
    await wrapper.get('#codex-ticket-max_attempts').setValue('')
    const invalid = wrapper.emitted('update:modelValue')?.at(-1)?.[0] as CodexTicketPolicy
    expect(Number.isNaN(invalid.max_attempts)).toBe(true)
    await wrapper.setProps({ modelValue: invalid })
    expect(wrapper.get('[role="alert"]').text()).toBe('invalid')
    expect(validCodexTicketPolicy(invalid)).toBe(false)
  })

  it('uses the same integer and range rules as the API', () => {
    expect(validCodexTicketPolicy(defaults)).toBe(true)
    for (const change of [
      { ttl_seconds: 59 }, { ttl_seconds: 86401 }, { ttl_seconds: 60.1 },
      { refresh_before_seconds: -1 }, { refresh_before_seconds: 3600 },
      { max_attempts: 0 }, { max_attempts: 11 }, { max_attempts: 1.5 },
      { failure_cooldown_seconds: 59 }, { failure_cooldown_seconds: 86401 }
    ]) expect(validCodexTicketPolicy({ ...defaults, ...change })).toBe(false)
    expect(validCodexTicketPolicy({ ttl_seconds: 60, refresh_before_seconds: 0, max_attempts: 1, failure_cooldown_seconds: 60 })).toBe(true)
    expect(validCodexTicketPolicy({ ttl_seconds: 86400, refresh_before_seconds: 86399, max_attempts: 10, failure_cooldown_seconds: 86400 })).toBe(true)
  })
})
