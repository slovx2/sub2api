import type { BasePaginationResponse } from '@/types'
import { apiClient } from './client'

export type LegacyPaymentChannel = 'alipay' | 'wxpay'

export interface CreateLegacyPaymentOrderRequest {
  amount: number
  channel: LegacyPaymentChannel
  device?: string
}

export interface LegacyPaymentConfig {
  enabled: boolean
  min_amount: number
  max_amount: number
  step: number
}

export interface LegacyPaymentOrder {
  id: number
  order_no: string
  status: string
  amount: number
  channel: LegacyPaymentChannel
  pay_type: string
  pay_info: string
  created_at: string
  paid_at?: string
  credited_at?: string
}

export type CreateLegacyPaymentOrderResponse = Pick<
  LegacyPaymentOrder,
  'id' | 'order_no' | 'status' | 'amount' | 'channel' | 'pay_type' | 'pay_info'
>

export async function createLegacyPaymentOrder(
  payload: CreateLegacyPaymentOrderRequest
): Promise<CreateLegacyPaymentOrderResponse> {
  const { data } = await apiClient.post<CreateLegacyPaymentOrderResponse>('/payments/orders', payload)
  return data
}

export async function getLegacyPaymentOrder(orderId: number): Promise<LegacyPaymentOrder> {
  const { data } = await apiClient.get<LegacyPaymentOrder>(`/payments/orders/${orderId}`)
  return data
}

export async function listLegacyPaymentOrders(
  page: number = 1,
  pageSize: number = 10
): Promise<BasePaginationResponse<LegacyPaymentOrder>> {
  const { data } = await apiClient.get<BasePaginationResponse<LegacyPaymentOrder>>('/payments/orders', {
    params: { page, page_size: pageSize }
  })
  return data
}

export async function getLegacyPaymentConfig(): Promise<LegacyPaymentConfig> {
  const { data } = await apiClient.get<LegacyPaymentConfig>('/payments/config')
  return data
}

export const legacyPaymentAPI = {
  createOrder: createLegacyPaymentOrder,
  getOrder: getLegacyPaymentOrder,
  listOrders: listLegacyPaymentOrders,
  getConfig: getLegacyPaymentConfig
}

export default legacyPaymentAPI
