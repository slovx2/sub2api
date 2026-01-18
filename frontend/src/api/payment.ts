import type { BasePaginationResponse } from '@/types'
import { apiClient } from './client'

export type PaymentChannel = 'alipay' | 'wxpay'

export interface CreatePaymentOrderRequest {
  amount: number
  channel: PaymentChannel
  device?: string
}

export interface PaymentConfig {
  enabled: boolean
  min_amount: number
  max_amount: number
  step: number
}

export interface PaymentOrder {
  id: number
  order_no: string
  status: string
  amount: number
  channel: PaymentChannel
  pay_type: string
  pay_info: string
  created_at: string
  paid_at?: string
  credited_at?: string
}

export type CreatePaymentOrderResponse = Pick<
  PaymentOrder,
  'id' | 'order_no' | 'status' | 'amount' | 'channel' | 'pay_type' | 'pay_info'
>

export async function createOrder(
  payload: CreatePaymentOrderRequest
): Promise<CreatePaymentOrderResponse> {
  const { data } = await apiClient.post<CreatePaymentOrderResponse>('/payments/orders', payload)
  return data
}

export async function getOrder(orderId: number): Promise<PaymentOrder> {
  const { data } = await apiClient.get<PaymentOrder>(`/payments/orders/${orderId}`)
  return data
}

export async function listOrders(
  page: number = 1,
  pageSize: number = 10
): Promise<BasePaginationResponse<PaymentOrder>> {
  const { data } = await apiClient.get<BasePaginationResponse<PaymentOrder>>('/payments/orders', {
    params: { page, page_size: pageSize }
  })
  return data
}

export async function getConfig(): Promise<PaymentConfig> {
  const { data } = await apiClient.get<PaymentConfig>('/payments/config')
  return data
}

export const paymentAPI = {
  createOrder,
  getOrder,
  listOrders,
  getConfig
}

export default paymentAPI
