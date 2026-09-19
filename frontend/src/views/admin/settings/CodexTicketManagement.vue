<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { getCodexTicketLogs, getCodexTicketOverview } from '@/api/admin/codexTickets'
import type { CodexTicketLogPage, CodexTicketOverview } from '@/api/admin/codexTickets'

const { t } = useI18n()
const tr = (key: string, params: Record<string, number | string> = {}) => t(`admin.settings.gatewayForwarding.ticketManagement.${key}`, params)
const overview = ref<CodexTicketOverview>()
const problems = ref<CodexTicketOverview>()
const logs = ref<CodexTicketLogPage>()
const overviewPage = ref(1)
const problemPage = ref(1)
const logPage = ref(1)
const accountId = ref('')
const result = ref('')
const tab = ref<'problems' | 'logs'>('logs')
const autoRefresh = ref(false)
const loading = ref(false)
const error = ref(false)
let controller: AbortController | undefined
let timer: ReturnType<typeof setInterval> | undefined

async function refresh() {
  controller?.abort()
  const current = new AbortController()
  controller = current
  loading.value = true
  error.value = false
  try {
    const [nextOverview, nextProblems, nextLogs] = await Promise.all([
      getCodexTicketOverview(overviewPage.value, false, current.signal),
      getCodexTicketOverview(problemPage.value, true, current.signal),
      getCodexTicketLogs(logPage.value, Number(accountId.value) || undefined, result.value, current.signal)
    ])
    if (current.signal.aborted) return
    overview.value = nextOverview
    problems.value = nextProblems
    logs.value = nextLogs
  } catch {
    if (!current.signal.aborted) error.value = true
  } finally {
    if (controller === current) loading.value = false
  }
}

function filterLogs() {
  logPage.value = 1
  void refresh()
}

function move(section: 'overview' | 'problems' | 'logs', delta: number) {
  const page = section === 'overview' ? overviewPage : section === 'problems' ? problemPage : logPage
  page.value += delta
  void refresh()
}

const pages = (total = 0, size = 20) => Math.max(1, Math.ceil(total / size))
const date = (value?: string) => value ? new Date(value).toLocaleString() : '—'
const reasons = new Set(['accepted', 'token_error', 'request_error', 'http_error', 'missing_state', 'invalid_length', 'invalid_format', 'scope_changed_or_cancelled', 'no_valid_ticket', 'harvest_not_configured', 'attempts_exhausted', 'cooldown_persist_failed'])
const reason = (value: string) => reasons.has(value) ? tr(`reasons.${value}`) : value

onMounted(() => {
  void refresh()
  timer = setInterval(() => { if (autoRefresh.value && !loading.value) void refresh() }, 15000)
})
onBeforeUnmount(() => { controller?.abort(); clearInterval(timer) })
</script>

<template>
  <div class="space-y-6" data-testid="codex-ticket-management" :aria-busy="loading">
    <p class="text-sm text-gray-500">{{ tr('savedPolicy') }}</p>
    <p v-if="error" role="alert" class="text-sm text-red-600">{{ tr('loadError') }}</p>
    <section class="rounded-2xl border border-gray-200 p-5 dark:border-dark-600">
      <div class="flex items-center justify-between gap-3">
        <h3 class="text-lg font-semibold">{{ tr('overview') }}</h3>
        <button type="button" class="btn btn-secondary" :disabled="loading" @click="refresh">{{ tr('refresh') }}</button>
      </div>
      <template v-if="overview">
        <p class="mt-2 text-sm text-gray-500">{{ overview.enabled ? tr('enabled') : tr('disabled') }} · {{ tr('overviewSummary', { accounts: overview.accounts, tickets: overview.valid_tickets }) }}</p>
        <div class="mt-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
          <article v-for="ticket in overview.items" :key="`${ticket.account_id}-${ticket.model}`" class="rounded-xl border border-gray-200 bg-gray-50 p-4 dark:border-dark-600 dark:bg-dark-800">
            <div class="flex items-start justify-between gap-2">
              <span class="font-semibold break-all">{{ ticket.account_name }} (#{{ ticket.account_id }})</span>
              <span :class="ticket.ready ? 'bg-teal-600 text-white' : 'bg-gray-200 text-gray-700'" class="rounded-full px-2 text-sm font-semibold">{{ ticket.ready ? ticket.length : tr('unavailable') }}</span>
            </div>
            <p class="my-2 font-mono text-sm break-all">{{ ticket.model }}</p>
            <p v-if="ticket.blocked" class="text-sm text-amber-600">{{ tr('blocked') }} · {{ date(ticket.cooldown_until) }}<br />{{ ticket.cooldown_reason }}</p>
            <p v-else-if="ticket.ready" class="text-sm text-teal-600">{{ tr('remaining', { minutes: Math.ceil(ticket.remaining_seconds / 60) }) }} · {{ tr('expires') }} {{ date(ticket.expires_at) }}</p>
            <p v-else class="text-sm text-amber-600">{{ tr('pending') }}</p>
          </article>
        </div>
        <p v-if="!overview.items.length" class="py-4 text-sm text-gray-500">{{ tr('noTickets') }}</p>
        <div v-if="overview.total > 12" class="mt-4 flex items-center gap-3 text-sm">
          <button type="button" class="btn btn-secondary" :disabled="loading || overviewPage <= 1" :aria-label="tr('previous')" @click="move('overview', -1)">‹</button>
          <span>{{ overviewPage }} / {{ pages(overview.total, 12) }}</span>
          <button type="button" class="btn btn-secondary" :disabled="loading || overviewPage >= pages(overview.total, 12)" :aria-label="tr('next')" @click="move('overview', 1)">›</button>
        </div>
      </template>
    </section>

    <section class="rounded-2xl border border-gray-200 p-5 dark:border-dark-600">
      <div class="flex flex-wrap items-center justify-between gap-3">
        <h3 class="text-lg font-semibold">{{ tr('diagnostics') }}</h3>
        <div class="flex items-center gap-3">
          <label class="flex items-center gap-2 text-sm"><input v-model="autoRefresh" type="checkbox" />{{ tr('autoRefresh') }}</label>
          <button type="button" class="btn btn-secondary" :disabled="loading" @click="refresh">{{ tr('refresh') }}</button>
        </div>
      </div>
      <p class="mt-2 text-sm text-gray-500">{{ tr('diagnosticHint') }}</p>
      <div v-if="logs" class="my-4 grid grid-cols-2 gap-3 lg:grid-cols-4">
        <div v-for="key in (['attempts', 'success', 'failure', 'injection_missing'] as const)" :key="key" class="rounded-xl border border-gray-200 p-4 dark:border-dark-600">
          <strong class="text-2xl" :class="{ 'text-green-600': key === 'success', 'text-red-600': key === 'failure', 'text-amber-600': key === 'injection_missing' }">{{ logs.summary[key] }}</strong>
          <p class="text-sm text-gray-500">{{ tr(key) }}</p>
        </div>
      </div>
      <div class="mb-4 flex gap-5 border-b border-gray-200 dark:border-dark-600">
        <button type="button" class="pb-2" :class="{ 'border-b-2 border-teal-600 text-teal-600': tab === 'problems' }" @click="tab = 'problems'">{{ tr('problems') }} ({{ problems?.problem_accounts ?? '—' }})</button>
        <button type="button" class="pb-2" :class="{ 'border-b-2 border-teal-600 text-teal-600': tab === 'logs' }" @click="tab = 'logs'">{{ tr('logs') }} ({{ logs?.total ?? '—' }})</button>
      </div>
      <template v-if="tab === 'problems' && problems">
        <p class="mb-3 text-sm text-gray-500">{{ tr('problemHint') }}</p>
        <div v-for="item in problems.items" :key="`${item.account_id}-${item.model}`" class="flex flex-wrap gap-3 border-b border-gray-100 py-3 text-sm dark:border-dark-700">
          <span>{{ item.account_name }} (#{{ item.account_id }})</span><span class="font-mono">{{ item.model }}</span><span class="text-amber-600">{{ item.blocked ? tr('blocked') : tr('pending') }}<template v-if="item.blocked"> · {{ date(item.cooldown_until) }} · {{ item.cooldown_reason }}</template></span>
        </div>
        <p v-if="!problems.items.length" class="py-6 text-center text-gray-500">{{ tr('noProblems') }}</p>
        <div v-if="problems.total > 12" class="mt-4 flex items-center gap-3">
          <button type="button" class="btn btn-secondary" :disabled="loading || problemPage <= 1" :aria-label="tr('previous')" @click="move('problems', -1)">‹</button>
          <span>{{ problemPage }} / {{ pages(problems.total, 12) }}</span>
          <button type="button" class="btn btn-secondary" :disabled="loading || problemPage >= pages(problems.total, 12)" :aria-label="tr('next')" @click="move('problems', 1)">›</button>
        </div>
      </template>
      <template v-if="tab === 'logs'">
        <div class="mb-3 flex flex-wrap gap-2">
          <input v-model="accountId" type="number" min="1" class="input w-40" :aria-label="tr('accountId')" :placeholder="tr('accountId')" @keydown.enter.prevent="filterLogs" />
          <select v-model="result" class="input w-40" :aria-label="tr('result')" @change="filterLogs">
            <option value="">{{ tr('allResults') }}</option><option value="success">{{ tr('success') }}</option><option value="failure">{{ tr('failure') }}</option><option value="injection_missing">{{ tr('injection_missing') }}</option>
          </select>
          <button type="button" class="btn btn-secondary" :disabled="loading" @click="filterLogs">{{ tr('filter') }}</button>
        </div>
        <div class="overflow-x-auto">
          <table class="w-full whitespace-nowrap text-left text-sm">
            <thead><tr><th v-for="key in ['time', 'account', 'model', 'attempt', 'length', 'http', 'result', 'reason']" :key="key" class="px-2 py-3">{{ tr(key) }}</th></tr></thead>
            <tbody><tr v-for="entry in logs?.items" :key="entry.id" class="border-t border-gray-100 dark:border-dark-700">
              <td class="px-2 py-3">{{ date(entry.created_at) }}</td><td class="px-2">{{ entry.account_name }} (#{{ entry.account_id }})</td><td class="px-2 font-mono">{{ entry.model }}</td>
              <td class="px-2">{{ entry.attempt || '—' }}</td><td class="px-2">{{ entry.length }}</td><td class="px-2">{{ entry.http_status || '—' }}</td><td class="px-2" :class="entry.success ? 'text-green-600' : 'text-amber-600'">{{ entry.kind === 'cooldown' ? tr('cooldown') : entry.kind === 'injection_missing' ? tr('injection_missing') : entry.success ? tr('success') : tr('failure') }}</td><td class="px-2">{{ reason(entry.reason) }}</td>
            </tr></tbody>
          </table>
        </div>
        <p v-if="logs && !logs.items.length" class="py-6 text-center text-gray-500">{{ tr('noLogs') }}</p>
        <div v-if="logs" class="mt-4 flex items-center gap-3 text-sm">
          <button type="button" data-testid="ticket-logs-prev" class="btn btn-secondary" :disabled="loading || logPage <= 1" :aria-label="tr('previous')" @click="move('logs', -1)">‹</button>
          <span>{{ logPage }} / {{ pages(logs.total) }} · {{ tr('total', { total: logs.total }) }}</span>
          <button type="button" data-testid="ticket-logs-next" class="btn btn-secondary" :disabled="loading || logPage >= pages(logs.total)" :aria-label="tr('next')" @click="move('logs', 1)">›</button>
        </div>
      </template>
    </section>
  </div>
</template>
