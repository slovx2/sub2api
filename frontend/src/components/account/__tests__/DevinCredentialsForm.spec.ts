import { beforeEach, describe, expect, it, vi } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import DevinCredentialsForm from '../DevinCredentialsForm.vue'

const { post } = vi.hoisted(() => ({ post: vi.fn() }))
vi.mock('@/api/client', () => ({ apiClient: { post } }))
vi.mock('vue-i18n', () => ({ useI18n: () => ({ t: (key: string) => key }) }))

function mountForm() {
  return mount(DevinCredentialsForm, {
    props: { token: '', baseUrl: '', proxyId: 3, editing: true }
  })
}

describe('Devin 登录', () => {
  beforeEach(() => { post.mockReset() })

  it('使用选定代理生成链接，兑换后只更新凭据表单', async () => {
    post.mockResolvedValueOnce({ data: { auth_url: 'https://app.devin.ai/auth/cli/continue?state=test', session_id: 'test' } })
      .mockResolvedValueOnce({ data: { session_token: 'devin-session-token$test' } })
    const wrapper = mountForm()
    expect(wrapper.get('#devin-token').attributes('type')).toBe('password')
    expect(wrapper.get('#devin-token').attributes('placeholder')).toContain('keepToken')
    await wrapper.get('button').trigger('click')
    await flushPromises()
    expect(post).toHaveBeenNthCalledWith(1, '/admin/devin/oauth/auth-url', { proxy_id: 3 })
    expect(wrapper.get('a').attributes('href')).toContain('https://app.devin.ai/')
    await wrapper.get('input[autocomplete="off"]').setValue('code-123')
    await wrapper.findAll('button')[1]!.trigger('click')
    await flushPromises()
    expect(post).toHaveBeenNthCalledWith(2, '/admin/devin/oauth/exchange-code', { session_id: 'test', code: 'code-123' })
    expect(wrapper.emitted('update:token')?.[0]).toEqual(['devin-session-token$test'])
    expect(wrapper.find('a').exists()).toBe(false)
    expect(wrapper.get('[role="status"]').text()).toContain('received')
    wrapper.unmount()
  })

  it('代理变化使尚未完成的登录请求失效', async () => {
    let resolve!: (value: unknown) => void
    post.mockReturnValueOnce(new Promise(r => { resolve = r }))
    const wrapper = mountForm()
    await wrapper.get('button').trigger('click')
    await wrapper.setProps({ proxyId: 4 })
    resolve({ data: { auth_url: 'https://app.devin.ai/old', session_id: 'old' } })
    await flushPromises()
    expect(wrapper.find('a').exists()).toBe(false)
    expect(wrapper.emitted('update:token')).toBeUndefined()
    wrapper.unmount()
  })

  it('失败提示不显示上游错误响应中的敏感内容', async () => {
    post.mockRejectedValue(new Error('secret-session-token'))
    const wrapper = mountForm()
    await wrapper.get('button').trigger('click')
    await flushPromises()
    expect(wrapper.get('[role="alert"]').text()).not.toContain('secret')
    expect(wrapper.get('button').attributes('disabled')).toBeUndefined()
    wrapper.unmount()
  })
})
