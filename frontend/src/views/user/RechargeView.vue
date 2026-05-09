<template>
  <AppLayout>
  <div class="space-y-6">
    <div class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
      <div>
        <h1 class="text-2xl font-semibold text-gray-900 dark:text-white">余额充值</h1>
        <p class="mt-1 text-sm text-gray-500 dark:text-dark-400">通过 Plugins World 支付为账户余额充值</p>
      </div>
      <button
        class="btn btn-secondary"
        type="button"
        :disabled="loadingOrders"
        @click="loadOrders"
      >
        刷新订单
      </button>
    </div>

    <div v-if="paidHint" class="rounded-md border border-green-200 bg-green-50 p-4 text-sm text-green-800 dark:border-green-800 dark:bg-green-900/20 dark:text-green-200">
      支付结果正在确认中，余额到账后订单会更新为已入账。
    </div>

    <div class="grid gap-6 lg:grid-cols-[minmax(0,1fr)_380px]">
      <section class="rounded-lg border border-gray-200 bg-white p-6 shadow-sm dark:border-dark-700 dark:bg-dark-800">
        <div class="mb-5">
          <h2 class="text-lg font-semibold text-gray-900 dark:text-white">创建充值订单</h2>
          <p v-if="config" class="mt-1 text-sm text-gray-500 dark:text-dark-400">
            单笔金额 {{ config.min_amount }} - {{ config.max_amount }} 元，步长 {{ config.step }} 元
          </p>
        </div>

        <div v-if="config && !config.enabled" class="rounded-md border border-yellow-200 bg-yellow-50 p-4 text-sm text-yellow-800 dark:border-yellow-800 dark:bg-yellow-900/20 dark:text-yellow-200">
          当前充值服务未启用。
        </div>

        <form class="space-y-5" @submit.prevent="submitOrder">
          <div>
            <label class="input-label" for="legacy-recharge-amount">充值金额</label>
            <input
              id="legacy-recharge-amount"
              v-model.number="form.amount"
              class="input"
              type="number"
              min="1"
              step="1"
              :disabled="submitting || !canCreateOrder"
              placeholder="请输入充值金额"
            />
          </div>

          <div>
            <label class="input-label">支付方式</label>
            <div class="grid grid-cols-2 gap-3">
              <button
                v-for="option in channelOptions"
                :key="option.value"
                class="rounded-md border px-4 py-3 text-left text-sm transition-colors"
                :class="form.channel === option.value
                  ? 'border-primary-500 bg-primary-50 text-primary-700 dark:border-primary-400 dark:bg-primary-900/20 dark:text-primary-200'
                  : 'border-gray-200 bg-white text-gray-700 hover:border-primary-300 dark:border-dark-600 dark:bg-dark-800 dark:text-dark-200'"
                type="button"
                :disabled="submitting || !canCreateOrder"
                @click="form.channel = option.value"
              >
                <span class="block font-medium">{{ option.label }}</span>
                <span class="mt-1 block text-xs text-gray-500 dark:text-dark-400">{{ option.description }}</span>
              </button>
            </div>
          </div>

          <button class="btn btn-primary w-full" type="submit" :disabled="submitting || !canCreateOrder">
            {{ submitting ? '正在创建订单...' : '立即充值' }}
          </button>
        </form>
      </section>

      <section class="rounded-lg border border-gray-200 bg-white p-6 shadow-sm dark:border-dark-700 dark:bg-dark-800">
        <h2 class="text-lg font-semibold text-gray-900 dark:text-white">最近订单</h2>
        <div v-if="loadingOrders" class="mt-5 text-sm text-gray-500 dark:text-dark-400">正在加载...</div>
        <div v-else-if="orders.length === 0" class="mt-5 text-sm text-gray-500 dark:text-dark-400">暂无充值订单</div>
        <div v-else class="mt-5 divide-y divide-gray-100 dark:divide-dark-700">
          <router-link
            v-for="order in orders"
            :key="order.id"
            class="block py-4 hover:bg-gray-50 dark:hover:bg-dark-700/40"
            :to="`/recharge/orders/${order.id}`"
          >
            <div class="flex items-center justify-between gap-3">
              <div class="min-w-0">
                <p class="truncate text-sm font-medium text-gray-900 dark:text-white">{{ order.order_no }}</p>
                <p class="mt-1 text-xs text-gray-500 dark:text-dark-400">{{ order.created_at }}</p>
              </div>
              <div class="text-right">
                <p class="text-sm font-semibold text-gray-900 dark:text-white">{{ order.amount }} 元</p>
                <p class="mt-1 text-xs" :class="statusClass(order.status)">{{ statusText(order.status) }}</p>
              </div>
            </div>
          </router-link>
        </div>
      </section>
    </div>
  </div>
  </AppLayout>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { legacyPaymentAPI, type LegacyPaymentChannel, type LegacyPaymentConfig, type LegacyPaymentOrder } from '@/api/legacyPayment'
import AppLayout from '@/components/layout/AppLayout.vue'
import { useAppStore } from '@/stores/app'

const route = useRoute()
const router = useRouter()
const appStore = useAppStore()

const config = ref<LegacyPaymentConfig | null>(null)
const orders = ref<LegacyPaymentOrder[]>([])
const loadingConfig = ref(false)
const loadingOrders = ref(false)
const submitting = ref(false)
const paidHint = computed(() => route.query.paid === '1')

const form = reactive<{
  amount: number | null
  channel: LegacyPaymentChannel
}>({
  amount: null,
  channel: 'alipay'
})

const channelOptions: Array<{ value: LegacyPaymentChannel; label: string; description: string }> = [
  { value: 'alipay', label: '支付宝', description: '跳转到支付宝支付' },
  { value: 'wxpay', label: '微信支付', description: '跳转到微信支付' }
]

const canCreateOrder = computed(() => Boolean(config.value?.enabled && !loadingConfig.value))

async function loadConfig(): Promise<void> {
  loadingConfig.value = true
  try {
    config.value = await legacyPaymentAPI.getConfig()
    if (!form.amount && config.value?.min_amount) {
      form.amount = config.value.min_amount
    }
  } catch (error) {
    console.error('Failed to load legacy payment config:', error)
    appStore.showError('加载充值配置失败')
  } finally {
    loadingConfig.value = false
  }
}

async function loadOrders(): Promise<void> {
  loadingOrders.value = true
  try {
    const result = await legacyPaymentAPI.listOrders(1, 10)
    orders.value = result.items || []
  } catch (error) {
    console.error('Failed to load legacy payment orders:', error)
    appStore.showError('加载充值订单失败')
  } finally {
    loadingOrders.value = false
  }
}

async function submitOrder(): Promise<void> {
  if (!config.value?.enabled) {
    appStore.showWarning('当前充值服务未启用')
    return
  }
  const amount = Number(form.amount)
  if (!Number.isFinite(amount) || amount <= 0) {
    appStore.showError('请输入有效的充值金额')
    return
  }
  if (amount < config.value.min_amount || amount > config.value.max_amount || amount % config.value.step !== 0) {
    appStore.showError(`充值金额需在 ${config.value.min_amount} - ${config.value.max_amount} 元之间，并符合步长 ${config.value.step} 元`)
    return
  }

  submitting.value = true
  try {
    const order = await legacyPaymentAPI.createOrder({
      amount,
      channel: form.channel,
      device: 'pc'
    })
    await loadOrders()
    if (order.pay_info) {
      window.location.href = order.pay_info
      return
    }
    await router.push(`/recharge/orders/${order.id}`)
  } catch (error: any) {
    console.error('Failed to create legacy payment order:', error)
    appStore.showError(error?.message || '创建充值订单失败')
  } finally {
    submitting.value = false
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

function statusClass(status: string): string {
  if (status === 'credited') return 'text-green-600 dark:text-green-400'
  if (status === 'failed' || status === 'closed') return 'text-red-600 dark:text-red-400'
  return 'text-primary-600 dark:text-primary-400'
}

onMounted(async () => {
  await Promise.all([loadConfig(), loadOrders()])
})
</script>
