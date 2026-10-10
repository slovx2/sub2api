import { apiClient } from '../client'

export type ProbeProtocol = 'codex' | 'bps'
export interface ModelTraceTarget { protocol: ProbeProtocol; model: string; expected_model: string }
export interface ModelTraceConfig {
  enabled: boolean
  account_mode: 'all' | 'selected'
  account_ids: number[]
  auto_schedule_account_ids: number[]
  targets: ModelTraceTarget[]
  interval_minutes: number
  concurrency: number
}
export interface ModelTraceDetail {
  protocol: ProbeProtocol
  model: string
  expected_model: string
  upstream_model?: string
  status: 'pending' | 'success' | 'error'
  prediction?: string
  probability: number
  verdict: 'matched' | 'mismatched' | 'unknown'
  error?: string
  finished_at: string
  bank_version: string
  matched_since: string | null
}
export interface ModelTraceHistoryEntry extends Omit<ModelTraceDetail, 'matched_since'> { id: number }
export interface ModelTraceHistoryPage { items: ModelTraceHistoryEntry[]; next_cursor?: string }
export const getModelTraceHistory = async (params: { account_id: number; protocol?: ProbeProtocol; model?: string; cursor?: string }) =>
  (await apiClient.get<ModelTraceHistoryPage>('/admin/modeltrace/history', { params })).data
export interface ModelTraceSummary { enabled: boolean; running: boolean; auto_schedule: boolean; matched: number; mismatched: number; details: ModelTraceDetail[] }
export interface ModelTraceSettingsResponse { config: ModelTraceConfig; accounts: { id: number; name: string }[]; candidates: string[]; bank_version: string }
export const getModelTraceSettings = async () => (await apiClient.get<ModelTraceSettingsResponse>('/admin/settings/modeltrace')).data
export const saveModelTraceSettings = async (config: ModelTraceConfig) => (await apiClient.put<ModelTraceConfig>('/admin/settings/modeltrace', config)).data
export const runModelTrace = async () => (await apiClient.post<{ accepted: number; running: number; unavailable: number }>('/admin/modeltrace/run')).data
