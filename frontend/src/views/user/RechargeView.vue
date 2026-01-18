<template>
  <AppLayout>
    <div class="mx-auto max-w-3xl space-y-6">
      <div
        v-if="!paymentAvailable"
        class="card border-amber-200 bg-amber-50 dark:border-amber-800/40 dark:bg-amber-900/20"
      >
        <div class="p-6">
          <div class="flex items-start gap-4">
            <div
              class="flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-xl bg-amber-100 dark:bg-amber-900/30"
            >
              <Icon name="exclamationTriangle" size="md" class="text-amber-600 dark:text-amber-400" />
            </div>
            <div class="flex-1">
              <h3 class="text-sm font-semibold text-amber-800 dark:text-amber-300">充值暂未开放</h3>
              <p class="mt-2 text-sm text-amber-700 dark:text-amber-400">
                请联系管理员开启支付功能
              </p>
            </div>
          </div>
        </div>
      </div>

      <template v-else>
        <div class="card overflow-hidden">
          <div class="bg-gradient-to-br from-primary-500 to-primary-600 px-6 py-8 text-center">
            <div
              class="mb-4 inline-flex h-16 w-16 items-center justify-center rounded-2xl bg-white/20 backdrop-blur-sm"
            >
              <Icon name="dollar" size="xl" class="text-white" />
            </div>
            <p class="text-sm font-medium text-primary-100">当前余额</p>
            <p class="mt-2 text-4xl font-bold text-white">
              {{ formatCurrency(user?.balance || 0) }}
            </p>
            <p class="mt-2 text-sm text-primary-100">1 元 = 1 美元</p>
          </div>
        </div>

        <div class="card">
          <div class="p-6">
            <form class="space-y-5" @submit.prevent="handleCreateOrder">
              <div>
                <label class="input-label" for="amount">充值金额</label>
                <input
                  id="amount"
                  v-model.number="amount"
                  type="number"
                  :min="minAmount"
                  :max="maxAmount"
                  :step="stepAmount"
                  placeholder="请输入充值金额"
                  class="input mt-1"
                  :disabled="submitting"
                />
                <p class="input-hint">{{ amountHint }}</p>
              </div>

              <div>
                <p class="input-label">支付方式</p>
                <div class="mt-2 grid grid-cols-2 gap-3">
                  <button
                    type="button"
                    class="btn"
                    :class="channel === 'alipay' ? 'btn-primary' : 'btn-secondary'"
                    :disabled="submitting"
                    @click="channel = 'alipay'"
                  >
                    <Icon name="creditCard" size="sm" />
                    支付宝
                  </button>
                  <button
                    type="button"
                    class="btn"
                    :class="channel === 'wxpay' ? 'btn-primary' : 'btn-secondary'"
                    :disabled="submitting"
                    @click="channel = 'wxpay'"
                  >
                    <Icon name="creditCard" size="sm" />
                    微信
                  </button>
                </div>
              </div>

              <button
                type="submit"
                class="btn btn-primary w-full"
                :disabled="submitting || !amountValid"
              >
                <svg
                  v-if="submitting"
                  class="-ml-1 mr-2 h-5 w-5 animate-spin"
                  fill="none"
                  viewBox="0 0 24 24"
                >
                  <circle
                    class="opacity-25"
                    cx="12"
                    cy="12"
                    r="10"
                    stroke="currentColor"
                    stroke-width="4"
                  ></circle>
                  <path
                    class="opacity-75"
                    fill="currentColor"
                    d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                  ></path>
                </svg>
                <Icon v-else name="arrowRight" size="md" />
                {{ submitting ? '下单中...' : '去支付' }}
              </button>

              <p v-if="!amountValid && amount !== null" class="text-sm text-red-600 dark:text-red-400">
                请输入符合范围和步长的金额
              </p>
            </form>
          </div>
        </div>

        <transition name="fade">
          <div v-if="order" class="card">
            <div class="border-b border-gray-100 px-6 py-4 dark:border-dark-700">
              <div class="flex items-center justify-between">
                <h2 class="text-lg font-semibold text-gray-900 dark:text-white">
                  订单信息
                </h2>
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
                    <button
                      type="button"
                      class="btn btn-ghost btn-sm"
                      @click="copyToClipboard(order.order_no)"
                    >
                      <Icon name="copy" size="sm" />
                    </button>
                  </div>
                </div>
                <div>
                  <p class="text-gray-500 dark:text-dark-400">充值金额</p>
                  <p class="mt-1 text-gray-900 dark:text-white">
                    {{ order.amount }} 元
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
                  <p class="mt-1 text-gray-900 dark:text-white">
                    {{ formatDateTime(order.paid_at) }}
                  </p>
                </div>
                <div v-if="order.credited_at">
                  <p class="text-gray-500 dark:text-dark-400">到账时间</p>
                  <p class="mt-1 text-gray-900 dark:text-white">
                    {{ formatDateTime(order.credited_at) }}
                  </p>
                </div>
                <div v-if="order.pay_type">
                  <p class="text-gray-500 dark:text-dark-400">支付类型</p>
                  <p class="mt-1 text-gray-900 dark:text-white">{{ order.pay_type }}</p>
                </div>
              </div>

              <div v-if="payInfo" class="space-y-2">
                <div class="flex items-center justify-between text-sm">
                  <span class="text-gray-500 dark:text-dark-400">支付链接</span>
                  <button
                    type="button"
                    class="btn btn-ghost btn-sm"
                    @click="copyToClipboard(payInfo)"
                  >
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
                <button
                  type="button"
                  class="btn btn-primary"
                  :disabled="!payInfo"
                  @click="openPayment"
                >
                  <Icon name="externalLink" size="sm" />
                  打开支付页面
                </button>
                <button
                  type="button"
                  class="btn btn-secondary"
                  :disabled="refreshing"
                  @click="refreshOrder(true)"
                >
                  <Icon name="refresh" size="sm" :class="refreshing ? 'animate-spin' : ''" />
                  刷新状态
                </button>
              </div>

              <p v-if="polling" class="text-xs text-gray-500 dark:text-dark-400">
                正在同步订单状态...
              </p>
            </div>
          </div>
        </transition>

        <transition name="fade">
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
        </transition>

        <div class="card">
          <div class="border-b border-gray-100 px-6 py-4 dark:border-dark-700">
            <div class="flex items-center justify-between">
              <h2 class="text-lg font-semibold text-gray-900 dark:text-white">订单列表</h2>
              <button
                type="button"
                class="btn btn-secondary btn-sm"
                :disabled="ordersLoading"
                @click="loadOrders"
              >
                <Icon name="refresh" size="sm" :class="ordersLoading ? 'animate-spin' : ''" />
                刷新
              </button>
            </div>
          </div>
          <div class="p-6">
            <div v-if="ordersLoading" class="text-sm text-gray-500 dark:text-dark-400">
              正在加载订单...
            </div>
            <div v-else-if="orders.length === 0">
              <EmptyState title="暂无充值订单" description="充值后订单会显示在这里" />
            </div>
            <div v-else class="overflow-x-auto">
              <table class="min-w-full text-sm">
                <thead class="text-xs uppercase text-gray-500 dark:text-dark-400">
                  <tr>
                    <th class="px-3 py-2 text-left font-medium">订单号</th>
                    <th class="px-3 py-2 text-left font-medium">金额</th>
                    <th class="px-3 py-2 text-left font-medium">状态</th>
                    <th class="px-3 py-2 text-left font-medium">创建时间</th>
                    <th class="px-3 py-2 text-right font-medium">操作</th>
                  </tr>
                </thead>
                <tbody class="text-gray-700 dark:text-gray-200">
                  <tr
                    v-for="orderItem in orders"
                    :key="orderItem.id"
                    class="border-t border-gray-100 dark:border-dark-700"
                  >
                    <td class="px-3 py-3 font-mono">
                      <RouterLink
                        :to="`/recharge/orders/${orderItem.id}`"
                        class="text-primary-600 hover:text-primary-700 dark:text-primary-400"
                      >
                        {{ orderItem.order_no }}
                      </RouterLink>
                    </td>
                    <td class="px-3 py-3">{{ orderItem.amount }} 元</td>
                    <td class="px-3 py-3">
                      <span :class="['badge', statusBadgeClass(orderItem.status)]">
                        {{ statusLabel(orderItem.status) }}
                      </span>
                    </td>
                    <td class="px-3 py-3">{{ formatDateTime(orderItem.created_at) }}</td>
                    <td class="px-3 py-3 text-right">
                      <RouterLink
                        :to="`/recharge/orders/${orderItem.id}`"
                        class="btn btn-secondary btn-sm"
                      >
                        查看详情
                      </RouterLink>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
          <div class="border-t border-gray-100 px-6 py-4 dark:border-dark-700">
            <Pagination
              v-if="ordersPagination.total > 0"
              :page="ordersPagination.page"
              :total="ordersPagination.total"
              :page-size="ordersPagination.page_size"
              @update:page="handleOrderPageChange"
              @update:pageSize="handleOrderPageSizeChange"
            />
          </div>
        </div>
      </template>
    </div>
  </AppLayout>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import AppLayout from '@/components/layout/AppLayout.vue'
import EmptyState from '@/components/common/EmptyState.vue'
import Pagination from '@/components/common/Pagination.vue'
import { Icon } from '@/components/icons'
import { useAppStore } from '@/stores/app'
import { useAuthStore } from '@/stores/auth'
import { paymentAPI, type PaymentChannel, type PaymentConfig, type PaymentOrder } from '@/api/payment'
import { useClipboard } from '@/composables/useClipboard'
import { formatCurrency, formatDateTime } from '@/utils/format'

const route = useRoute()
const router = useRouter()
const appStore = useAppStore()
const authStore = useAuthStore()
const { copyToClipboard } = useClipboard()

const user = computed(() => authStore.user)
const paymentConfig = ref<PaymentConfig | null>(null)
const paymentAvailable = computed(() => !!paymentConfig.value?.enabled)

const minAmount = computed(() => {
  const value = paymentConfig.value?.min_amount
  return typeof value === 'number' && Number.isFinite(value) && value > 0 ? value : 5
})
const maxAmount = computed(() => {
  const value = paymentConfig.value?.max_amount
  return typeof value === 'number' && Number.isFinite(value) && value > 0 ? value : 5000
})
const stepAmount = computed(() => {
  const value = paymentConfig.value?.step
  return typeof value === 'number' && Number.isFinite(value) && value > 0 ? value : 1
})

const amount = ref<number>(0)
const channel = ref<PaymentChannel>('alipay')
const submitting = ref(false)
const refreshing = ref(false)
const errorMessage = ref('')
const order = ref<PaymentOrder | null>(null)
const polling = ref(false)
const pollTimer = ref<number | null>(null)
const orders = ref<PaymentOrder[]>([])
const ordersLoading = ref(false)
const ordersPagination = reactive({ page: 1, page_size: 10, total: 0 })

const payInfo = computed(() => order.value?.pay_info || '')
const payType = computed(() => order.value?.pay_type || '')
const amountHint = computed(
  () => `单笔 ${minAmount.value} ~ ${maxAmount.value} 元，步长 ${stepAmount.value} 元`
)

const amountValid = computed(() => {
  const value = amount.value
  if (!Number.isFinite(value)) {
    return false
  }
  if (value < minAmount.value || value > maxAmount.value) {
    return false
  }
  if (stepAmount.value > 0 && value % stepAmount.value !== 0) {
    return false
  }
  return true
})

const showQRCode = computed(() => {
  if (payType.value !== 'qrcode') {
    return false
  }
  return isImagePayInfo(payInfo.value)
})

function initAmount(): void {
  const min = minAmount.value
  const max = maxAmount.value
  let value = 10
  if (value < min) {
    value = min
  }
  if (value > max) {
    value = max
  }
  amount.value = value
}

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

function detectDevice(): string {
  const ua = navigator.userAgent.toLowerCase()
  if (ua.includes('micromessenger')) {
    return 'wechat'
  }
  if (ua.includes('alipayclient')) {
    return 'alipay'
  }
  if (ua.includes(' qq') || ua.includes('qq/')) {
    return 'qq'
  }
  if (ua.includes('iphone') || ua.includes('ipad') || ua.includes('android') || ua.includes('mobile')) {
    return 'mobile'
  }
  return 'pc'
}

function stopPolling(): void {
  if (pollTimer.value) {
    window.clearInterval(pollTimer.value)
    pollTimer.value = null
  }
  polling.value = false
}

function startPolling(): void {
  stopPolling()
  polling.value = true
  pollTimer.value = window.setInterval(() => {
    refreshOrder(false)
  }, 3000)
}

function shouldStopPolling(status: string): boolean {
  return ['credited', 'failed', 'closed'].includes(status)
}

async function loadConfig(): Promise<void> {
  try {
    paymentConfig.value = await paymentAPI.getConfig()
  } catch (_error) {
    paymentConfig.value = {
      enabled: false,
      min_amount: 5,
      max_amount: 5000,
      step: 1
    }
  }
}

async function handleCreateOrder(): Promise<void> {
  if (!amountValid.value) {
    errorMessage.value = ''
    return
  }
  errorMessage.value = ''
  submitting.value = true
  try {
    const result = await paymentAPI.createOrder({
      amount: amount.value,
      channel: channel.value,
      device: detectDevice()
    })
    const newOrder: PaymentOrder = {
      ...result,
      created_at: new Date().toISOString(),
      paid_at: undefined,
      credited_at: undefined
    }
    order.value = newOrder
    ordersPagination.page = 1
    await loadOrders()
    openPayment()
    startPolling()
  } catch (error) {
    errorMessage.value = (error as { message?: string }).message || '下单失败，请稍后重试'
  } finally {
    submitting.value = false
  }
}

async function refreshOrder(manual: boolean): Promise<void> {
  if (!order.value?.id) {
    return
  }
  if (manual) {
    refreshing.value = true
  }
  try {
    const latest = await paymentAPI.getOrder(order.value.id)
    const previousStatus = order.value.status
    order.value = latest
    if (latest.status === 'credited' && previousStatus !== 'credited') {
      await authStore.refreshUser()
    }
    if (latest.status !== previousStatus && shouldStopPolling(latest.status)) {
      await loadOrders()
    }
    if (shouldStopPolling(latest.status)) {
      stopPolling()
    }
  } catch (error) {
    errorMessage.value = (error as { message?: string }).message || '订单不存在或已失效'
    stopPolling()
  } finally {
    refreshing.value = false
  }
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

async function loadOrders(): Promise<void> {
  if (!paymentAvailable.value) {
    return
  }
  ordersLoading.value = true
  try {
    const result = await paymentAPI.listOrders(ordersPagination.page, ordersPagination.page_size)
    orders.value = result.items || []
    ordersPagination.total = result.total || 0
  } catch (error) {
    orders.value = []
    ordersPagination.total = 0
    errorMessage.value = (error as { message?: string }).message || '订单列表加载失败'
  } finally {
    ordersLoading.value = false
  }
}

async function handleReturnToast(): Promise<void> {
  const raw = route.query.paid
  const value = Array.isArray(raw) ? raw[0] : raw
  if (value !== '1') {
    return
  }
  await authStore.refreshUser()
  await loadOrders()
  const balance = formatCurrency(authStore.user?.balance || 0)
  appStore.showSuccess(`充值成功，当前余额 ${balance}`)
  router.replace({ path: '/recharge' })
}

function handleOrderPageChange(page: number): void {
  ordersPagination.page = page
  loadOrders()
}

function handleOrderPageSizeChange(size: number): void {
  ordersPagination.page_size = size
  ordersPagination.page = 1
  loadOrders()
}

watch([minAmount, maxAmount], () => {
  if (!amountValid.value) {
    initAmount()
  }
})

watch(
  () => paymentAvailable.value,
  (enabled) => {
    if (enabled) {
      loadOrders()
    }
  }
)

watch(
  () => route.query.paid,
  () => {
    handleReturnToast()
  }
)

onMounted(async () => {
  initAmount()
  await loadConfig()
  await loadOrders()
  await handleReturnToast()
})

onBeforeUnmount(() => {
  stopPolling()
})
</script>
