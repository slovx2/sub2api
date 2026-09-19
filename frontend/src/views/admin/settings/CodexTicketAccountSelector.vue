<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { list } from '@/api/admin/accounts'
import type { AccountListItem } from '@/types'

const props = defineProps<{ modelValue: number[] }>()
const emit = defineEmits<{ 'update:modelValue': [value: number[]] }>()
const { t } = useI18n()
const search = ref('')
const page = ref(1)
const pages = ref(1)
const accounts = ref<AccountListItem[]>([])
const names = ref<Record<number, string>>({})
const loading = ref(false)
const error = ref(false)
let controller: AbortController | undefined

function eligible(account: AccountListItem): boolean {
  return account.platform === 'openai' && ['oauth', 'setup-token'].includes(account.type)
    && account.status === 'active' && !account.parent_account_id
}

async function load(target = page.value) {
  controller?.abort()
  const current = new AbortController()
  controller = current
  loading.value = true
  error.value = false
  try {
    const result = await list(target, 20, { platform: 'openai', search: search.value.trim(), lite: 'true' }, { signal: current.signal })
    if (current.signal.aborted) return
    accounts.value = result.items
    page.value = target
    pages.value = Math.max(1, Math.ceil(result.total / 20))
    for (const account of result.items) names.value[account.id] = account.name
  } catch {
    if (!current.signal.aborted) error.value = true
  } finally {
    if (controller === current) loading.value = false
  }
}

function update(ids: number[]) {
  // 最后一个取消勾选也意味着全部生效，必须显式确认。
  if (!ids.length && props.modelValue.length && !window.confirm(t('admin.settings.gatewayForwarding.codexTicketAccountsClearConfirm'))) return
  emit('update:modelValue', [...new Set(ids)].sort((a, b) => a - b))
}

function toggle(id: number) {
  update(props.modelValue.includes(id) ? props.modelValue.filter(value => value !== id) : [...props.modelValue, id])
}

onMounted(() => load(1))
onBeforeUnmount(() => controller?.abort())
</script>

<template>
  <section class="space-y-3" data-testid="codex-ticket-account-selector">
    <h3 class="text-base font-semibold">{{ t('admin.settings.gatewayForwarding.codexTicketAccounts') }}</h3>
    <p class="text-sm text-gray-500">{{ t('admin.settings.gatewayForwarding.codexTicketAccountsHint') }}</p>
    <p class="text-sm font-medium" role="status">
      {{ modelValue.length ? t('admin.settings.gatewayForwarding.codexTicketAccountsSelected', { count: modelValue.length }) : t('admin.settings.gatewayForwarding.codexTicketAccountsAll') }}
    </p>
    <div v-if="modelValue.length" class="flex flex-wrap gap-2">
      <button v-for="id in modelValue" :key="id" type="button" class="btn btn-secondary text-xs" :data-selected-id="id" @click="toggle(id)">
        {{ names[id] ? `${names[id]} (#${id})` : `#${id}` }} ×
      </button>
      <button type="button" class="btn btn-secondary text-xs" data-testid="clear-ticket-accounts" @click="update([])">{{ t('admin.settings.gatewayForwarding.codexTicketAccountsClear') }}</button>
    </div>
    <div class="flex gap-2">
      <input v-model="search" class="input flex-1" :aria-label="t('admin.settings.gatewayForwarding.codexTicketAccountsSearch')" :placeholder="t('admin.settings.gatewayForwarding.codexTicketAccountsSearch')" @keydown.enter.prevent="load(1)" />
      <button type="button" class="btn btn-secondary" @click="load(1)">{{ t('common.search') }}</button>
    </div>
    <p v-if="error" class="text-sm text-red-600" role="alert">{{ t('admin.settings.gatewayForwarding.codexTicketAccountsLoadError') }}</p>
    <div class="max-h-64 overflow-auto rounded border border-gray-200 p-3 dark:border-dark-600" :aria-busy="loading">
      <label v-for="account in accounts" :key="account.id" class="flex items-center gap-2 py-1.5 text-sm">
        <input type="checkbox" :data-account-id="account.id" :checked="modelValue.includes(account.id)" :disabled="loading || (!eligible(account) && !modelValue.includes(account.id))" @change="toggle(account.id)" />
        <span>{{ account.name }} (#{{ account.id }})</span>
        <span v-if="!eligible(account)" class="text-gray-500">{{ t('admin.settings.gatewayForwarding.codexTicketAccountsUnavailable') }}</span>
      </label>
      <span v-if="!accounts.length && !loading" class="text-sm text-gray-500">{{ t('common.noData') }}</span>
    </div>
    <div class="flex items-center gap-3 text-sm">
      <button type="button" class="btn btn-secondary" data-testid="ticket-accounts-prev" :disabled="loading || page <= 1" @click="load(page - 1)">‹</button>
      <span>{{ page }} / {{ pages }}</span>
      <button type="button" class="btn btn-secondary" data-testid="ticket-accounts-next" :disabled="loading || page >= pages" @click="load(page + 1)">›</button>
    </div>
  </section>
</template>
