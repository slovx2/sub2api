import { apiClient } from '../client'

export type ProbeProtocol = 'codex' | 'bps'
export interface ModelTraceTarget { protocol: ProbeProtocol; model: string; expected_model: string }
export interface ModelTraceConfig {
  enabled: boolean
  account_mode: 'all' | 'selected'
  account_ids: number[]
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
}
export interface ModelTraceSummary { enabled: boolean; running: boolean; matched: number; mismatched: number; details: ModelTraceDetail[] }
export interface ModelTraceSettingsResponse { config: ModelTraceConfig; accounts: { id: number; name: string }[]; candidates: string[]; bank_version: string }
export const getModelTraceSettings = async () => (await apiClient.get<ModelTraceSettingsResponse>('/admin/settings/modeltrace')).data
export const saveModelTraceSettings = async (config: ModelTraceConfig) => (await apiClient.put<ModelTraceConfig>('/admin/settings/modeltrace', config)).data
export const runModelTrace = async () => (await apiClient.post<{ accepted: number; running: number; unavailable: number }>('/admin/modeltrace/run')).data
