<template>
  <div class="mx-auto max-w-3xl space-y-6">
    <div class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
      <div>
        <h1 class="text-2xl font-semibold text-gray-900 dark:text-white">充值订单</h1>
        <p class="mt-1 text-sm text-gray-500 dark:text-dark-400">查看订单支付和入账状态</p>
      </div>
      <router-link class="btn btn-secondary" to="/recharge">返回充值</router-link>
    </div>

    <section class="rounded-lg border border-gray-200 bg-white p-6 shadow-sm dark:border-dark-700 dark:bg-dark-800">
      <div v-if="loading" class="text-sm text-gray-500 dark:text-dark-400">正在加载...</div>
      <div v-else-if="!order" class="text-sm text-gray-500 dark:text-dark-400">订单不存在或无权查看</div>
      <div v-else class="space-y-5">
        <div class="flex items-start justify-between gap-4">
          <div class="min-w-0">
            <p class="text-sm text-gray-500 dark:text-dark-400">订单号</p>
            <p class="mt-1 break-all text-base font-medium text-gray-900 dark:text-white">{{ order.order_no }}</p>
          </div>
          <span class="rounded-full px-3 py-1 text-sm font-medium" :class="statusBadgeClass(order.status)">
            {{ statusText(order.status) }}
          </span>
        </div>

        <dl class="grid gap-4 sm:grid-cols-2">
          <div>
            <dt class="text-sm text-gray-500 dark:text-dark-400">充值金额</dt>
            <dd class="mt-1 text-base font-semibold text-gray-900 dark:text-white">{{ order.amount }} 元</dd>
          </div>
          <div>
            <dt class="text-sm text-gray-500 dark:text-dark-400">支付方式</dt>
            <dd class="mt-1 text-base text-gray-900 dark:text-white">{{ order.channel === 'wxpay' ? '微信支付' : '支付宝' }}</dd>
          </div>
          <div>
            <dt class="text-sm text-gray-500 dark:text-dark-400">创建时间</dt>
            <dd class="mt-1 text-base text-gray-900 dark:text-white">{{ order.created_at }}</dd>
          </div>
          <div v-if="order.paid_at">
            <dt class="text-sm text-gray-500 dark:text-dark-400">支付时间</dt>
            <dd class="mt-1 text-base text-gray-900 dark:text-white">{{ order.paid_at }}</dd>
          </div>
          <div v-if="order.credited_at">
            <dt class="text-sm text-gray-500 dark:text-dark-400">入账时间</dt>
            <dd class="mt-1 text-base text-gray-900 dark:text-white">{{ order.credited_at }}</dd>
          </div>
        </dl>

        <div class="flex flex-col gap-3 sm:flex-row">
          <button
            v-if="order.pay_info && (order.status === 'created' || order.status === 'paying')"
            class="btn btn-primary"
            type="button"
            @click="openPayment"
          >
            继续支付
          </button>
          <button class="btn btn-secondary" type="button" :disabled="loading" @click="loadOrder">
            刷新状态
          </button>
        </div>
      </div>
    </section>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { legacyPaymentAPI, type LegacyPaymentOrder } from '@/api/legacyPayment'
import { useAppStore } from '@/stores/app'

const route = useRoute()
const appStore = useAppStore()

const order = ref<LegacyPaymentOrder | null>(null)
const loading = ref(false)

async function loadOrder(): Promise<void> {
  const orderId = Number(route.params.id)
  if (!Number.isFinite(orderId) || orderId <= 0) {
    order.value = null
    return
  }

  loading.value = true
  try {
    order.value = await legacyPaymentAPI.getOrder(orderId)
  } catch (error) {
    console.error('Failed to load legacy payment order:', error)
    order.value = null
    appStore.showError('加载充值订单失败')
  } finally {
    loading.value = false
  }
}

function openPayment(): void {
  if (order.value?.pay_info) {
    window.location.href = order.value.pay_info
  }
}

function statusText(status: string): string {
  const labels: Record<string, string> = {
    created: '已创建',
    paying: '待支付',
    paid: '已支付',
    crediting: '入账中',
    credited: '已入账',
    failed: '失败',
    closed: '已关闭'
  }
  return labels[status] || status
}

function statusBadgeClass(status: string): string {
  if (status === 'credited') return 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300'
  if (status === 'failed' || status === 'closed') return 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300'
  return 'bg-primary-100 text-primary-700 dark:bg-primary-900/30 dark:text-primary-300'
}

onMounted(loadOrder)
</script>
