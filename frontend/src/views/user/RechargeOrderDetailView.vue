<template>
  <AppLayout>
    <div class="mx-auto max-w-3xl space-y-6">
      <div class="flex flex-wrap items-center justify-between gap-3">
        <h1 class="text-xl font-semibold text-gray-900 dark:text-white">订单详情</h1>
        <button type="button" class="btn btn-secondary" @click="goBack">
          <Icon name="arrowLeft" size="sm" />
          返回充值
        </button>
      </div>

      <div
        v-if="errorMessage"
        class="card border-red-200 bg-red-50 dark:border-red-800/50 dark:bg-red-900/20"
      >
        <div class="p-6">
          <div class="flex items-start gap-4">
            <div
              class="flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-xl bg-red-100 dark:bg-red-900/30"
            >
              <Icon name="exclamationCircle" size="md" class="text-red-600 dark:text-red-400" />
            </div>
            <div class="flex-1">
              <h3 class="text-sm font-semibold text-red-800 dark:text-red-300">
                {{ errorMessage }}
              </h3>
            </div>
          </div>
        </div>
      </div>

      <div v-else-if="loading" class="card">
        <div class="p-6 text-sm text-gray-500 dark:text-dark-400">正在加载订单...</div>
      </div>

      <div v-else-if="order" class="card">
        <div class="border-b border-gray-100 px-6 py-4 dark:border-dark-700">
          <div class="flex items-center justify-between">
            <h2 class="text-lg font-semibold text-gray-900 dark:text-white">订单信息</h2>
            <span :class="['badge', statusBadgeClass(order.status)]">
              {{ statusLabel(order.status) }}
            </span>
          </div>
        </div>
        <div class="space-y-4 p-6">
          <div class="grid gap-4 text-sm sm:grid-cols-2">
            <div>
              <p class="text-gray-500 dark:text-dark-400">订单号</p>
              <div class="mt-1 flex items-center gap-2">
                <span class="font-mono text-gray-900 dark:text-white">{{ order.order_no }}</span>
                <button type="button" class="btn btn-ghost btn-sm" @click="copyToClipboard(order.order_no)">
                  <Icon name="copy" size="sm" />
                </button>
              </div>
            </div>
            <div>
              <p class="text-gray-500 dark:text-dark-400">充值金额</p>
              <p class="mt-1 text-gray-900 dark:text-white">{{ order.amount }} 元</p>
            </div>
            <div>
              <p class="text-gray-500 dark:text-dark-400">支付方式</p>
              <p class="mt-1 text-gray-900 dark:text-white">
                {{ order.channel === 'wxpay' ? '微信' : '支付宝' }}
              </p>
            </div>
            <div v-if="order.created_at">
              <p class="text-gray-500 dark:text-dark-400">创建时间</p>
              <p class="mt-1 text-gray-900 dark:text-white">
                {{ formatDateTime(order.created_at) }}
              </p>
            </div>
            <div v-if="order.paid_at">
              <p class="text-gray-500 dark:text-dark-400">支付时间</p>
              <p class="mt-1 text-gray-900 dark:text-white">{{ formatDateTime(order.paid_at) }}</p>
            </div>
            <div v-if="order.credited_at">
              <p class="text-gray-500 dark:text-dark-400">到账时间</p>
              <p class="mt-1 text-gray-900 dark:text-white">{{ formatDateTime(order.credited_at) }}</p>
            </div>
            <div v-if="order.pay_type">
              <p class="text-gray-500 dark:text-dark-400">支付类型</p>
              <p class="mt-1 text-gray-900 dark:text-white">{{ order.pay_type }}</p>
            </div>
          </div>

          <div v-if="payInfo" class="space-y-2">
            <div class="flex items-center justify-between text-sm">
              <span class="text-gray-500 dark:text-dark-400">支付链接</span>
              <button type="button" class="btn btn-ghost btn-sm" @click="copyToClipboard(payInfo)">
                <Icon name="copy" size="sm" />
                复制链接
              </button>
            </div>
            <p class="break-all text-sm text-gray-700 dark:text-gray-300">{{ payInfo }}</p>
          </div>

          <div v-if="showQRCode" class="flex justify-center">
            <img
              :src="payInfo"
              alt="QR code"
              class="h-48 w-48 rounded-xl border border-gray-200 bg-white p-2 dark:border-dark-700"
            />
          </div>

          <div class="flex flex-wrap gap-3">
            <button type="button" class="btn btn-primary" :disabled="!payInfo" @click="openPayment">
              <Icon name="externalLink" size="sm" />
              打开支付页面
            </button>
          </div>
        </div>
      </div>
    </div>
  </AppLayout>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import AppLayout from '@/components/layout/AppLayout.vue'
import { Icon } from '@/components/icons'
import { paymentAPI, type PaymentOrder } from '@/api/payment'
import { useClipboard } from '@/composables/useClipboard'
import { formatDateTime } from '@/utils/format'

const route = useRoute()
const router = useRouter()
const { copyToClipboard } = useClipboard()

const order = ref<PaymentOrder | null>(null)
const loading = ref(false)
const errorMessage = ref('')

const payInfo = computed(() => order.value?.pay_info || '')
const payType = computed(() => order.value?.pay_type || '')
const showQRCode = computed(() => {
  if (payType.value !== 'qrcode') {
    return false
  }
  return isImagePayInfo(payInfo.value)
})

function statusLabel(status: string): string {
  const labels: Record<string, string> = {
    created: '待支付',
    paying: '支付中',
    paid: '已支付',
    crediting: '入账中',
    credited: '充值成功',
    failed: '支付失败',
    closed: '已关闭'
  }
  return labels[status] || status
}

function statusBadgeClass(status: string): string {
  switch (status) {
    case 'created':
    case 'paying':
      return 'badge-warning'
    case 'paid':
    case 'crediting':
      return 'badge-primary'
    case 'credited':
      return 'badge-success'
    case 'failed':
      return 'badge-danger'
    case 'closed':
      return 'badge-gray'
    default:
      return 'badge-gray'
  }
}

function isImagePayInfo(info: string): boolean {
  if (!info) {
    return false
  }
  return info.startsWith('http://') || info.startsWith('https://') || info.startsWith('data:image/')
}

function openPayment(): void {
  if (!payInfo.value) {
    return
  }
  if (payType.value === 'html') {
    const popup = window.open('', '_blank')
    if (popup) {
      popup.document.write(payInfo.value)
      popup.document.close()
    }
    return
  }
  if (payInfo.value.startsWith('http://') || payInfo.value.startsWith('https://')) {
    window.open(payInfo.value, '_blank', 'noopener')
    return
  }
  window.location.href = payInfo.value
}

function goBack(): void {
  router.push('/recharge')
}

async function loadOrder(): Promise<void> {
  const raw = route.params.id
  const orderId = Number.parseInt(String(raw), 10)
  if (!Number.isFinite(orderId) || orderId <= 0) {
    errorMessage.value = '订单不存在或已失效'
    return
  }
  loading.value = true
  errorMessage.value = ''
  try {
    order.value = await paymentAPI.getOrder(orderId)
  } catch (error) {
    errorMessage.value = (error as { message?: string }).message || '订单不存在或已失效'
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  loadOrder()
})
</script>
