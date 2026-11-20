import { beforeEach, describe, expect, it, vi } from 'vitest'

const { get, put } = vi.hoisted(() => ({
  get: vi.fn(),
  put: vi.fn()
}))

vi.mock('@/api/client', () => ({
  apiClient: { get, put }
}))

import { getOpenAIImagePriorityAccounts, updateOpenAIImagePriorityAccounts } from '@/api/admin/accounts'

describe('admin OpenAI image priority accounts API', () => {
  beforeEach(() => {
    get.mockReset()
    put.mockReset()
  })

  it('reads and replaces the global account list', async () => {
    const value = {
      account_ids: [3, 9],
      accounts: [
        { id: 3, name: 'img-a', type: 'oauth', status: 'active', schedulable: false, priority: 1, concurrency: 5 }
      ]
    }
    get.mockResolvedValueOnce({ data: value })
    put.mockResolvedValueOnce({ data: { account_ids: [3], accounts: value.accounts } })

    await expect(getOpenAIImagePriorityAccounts()).resolves.toEqual(value)
    await expect(updateOpenAIImagePriorityAccounts([3])).resolves.toMatchObject({ account_ids: [3] })
    expect(get).toHaveBeenCalledWith('/admin/accounts/openai-image-priority')
    expect(put).toHaveBeenCalledWith('/admin/accounts/openai-image-priority', { account_ids: [3] })
  })
})
