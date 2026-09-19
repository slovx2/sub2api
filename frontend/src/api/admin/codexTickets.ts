import { apiClient } from '../client'

export interface CodexTicketOverviewItem {
  account_id: number
  account_name: string
  model: string
  length?: number
  ready: boolean
  blocked: boolean
  remaining_seconds: number
  expires_at?: string
}

export interface CodexTicketOverview {
  enabled: boolean
  accounts: number
  valid_tickets: number
  problem_accounts: number
  total: number
  items: CodexTicketOverviewItem[]
}

export interface CodexTicketEvent {
  id: number
  account_id: number
  account_name: string
  model: string
  kind: 'harvest' | 'injection_missing'
  length: number
  http_status: number
  success: boolean
  reason: string
  created_at: string
}

export interface CodexTicketLogPage {
  items: CodexTicketEvent[]
  total: number
  summary: { attempts: number; success: number; failure: number; injection_missing: number }
}

export async function getCodexTicketOverview(page = 1, problemsOnly = false, signal?: AbortSignal): Promise<CodexTicketOverview> {
  const { data } = await apiClient.get('/admin/settings/codex-tickets/overview', {
    params: { page, page_size: 12, problems_only: problemsOnly }, signal
  })
  return data
}

export async function getCodexTicketLogs(page = 1, accountId?: number, result?: string, signal?: AbortSignal): Promise<CodexTicketLogPage> {
  const { data } = await apiClient.get('/admin/settings/codex-tickets/logs', {
    params: { page, page_size: 20, account_id: accountId, result: result || undefined }, signal
  })
  return data
}
