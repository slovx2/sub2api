<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { useAppStore } from '@/stores'
import { getModelTraceSettings, saveModelTraceSettings, runModelTrace, type ModelTraceConfig, type ProbeProtocol, type ModelTraceTarget } from '@/api/admin/modeltrace'
import { extractApiErrorMessage } from '@/utils/apiError'

const { t } = useI18n()
const app = useAppStore()
const config = ref<ModelTraceConfig>()
const accounts = ref<{ id: number; name: string }[]>([])
const candidates = ref<string[]>([])
const saved = ref('')
const search = ref('')
const busy = ref(false)
const loadError = ref(false)
const protocols: ProbeProtocol[] = ['codex', 'bps']
// 编辑、删除相邻行不改变当前行的身份，也不将界面标识发送给后端。
const targetKeys = new WeakMap<ModelTraceTarget, number>()
let nextTargetKey = 0
function targetKey(target: ModelTraceTarget): number {
  let key = targetKeys.get(target)
  if (key === undefined) { key = nextTargetKey++; targetKeys.set(target, key) }
  return key
}
const dirty = computed(() => JSON.stringify(config.value) !== saved.value)
const filtered = computed(() => accounts.value.filter(a => a.name.toLowerCase().includes(search.value.toLowerCase())))
async function load() {
  loadError.value = false
  try {
    const result = await getModelTraceSettings()
    config.value = result.config; accounts.value = result.accounts; candidates.value = result.candidates
    saved.value = JSON.stringify(result.config)
  } catch { loadError.value = true }
}
function toggleProtocol(protocol: ProbeProtocol, enabled: boolean) {
  if (!config.value) return
  if (enabled) config.value.targets.push({ protocol, model: '', expected_model: '' })
  else config.value.targets = config.value.targets.filter(target => target.protocol !== protocol)
}
function selectAll() { if (config.value) config.value.account_ids = accounts.value.map(a => a.id) }
async function save() {
  if (!config.value) return
  busy.value = true
  try {
    config.value = await saveModelTraceSettings(config.value)
    saved.value = JSON.stringify(config.value)
    app.showSuccess(t('modeltrace.saved'))
  } catch (error) { app.showError(extractApiErrorMessage(error, t('modeltrace.error'))) } finally { busy.value = false }
}
async function run() {
  busy.value = true
  try { app.showSuccess(t('modeltrace.queued', await runModelTrace())) }
  catch (error) { app.showError(extractApiErrorMessage(error, t('modeltrace.error'))) } finally { busy.value = false }
}
onMounted(load)
</script>

<template>
  <section class="card space-y-4 p-6" aria-labelledby="modeltrace-title">
    <div>
      <h3 id="modeltrace-title" class="text-lg font-medium text-gray-900 dark:text-white">ModelTrace</h3>
      <p class="mt-1 text-sm text-gray-500">{{ t('modeltrace.description') }}</p>
    </div>
    <button v-if="loadError" class="btn btn-secondary" type="button" @click="load">{{ t('modeltrace.retry') }}</button>
    <p v-else-if="!config" class="text-sm text-gray-500">{{ t('modeltrace.loading') }}</p>
    <div v-else class="space-y-4">
      <label class="flex items-center gap-2 text-sm"><input v-model="config.enabled" type="checkbox">{{ t('modeltrace.enabled') }}</label>
      <div class="flex flex-wrap gap-4 text-sm">
        <label class="flex items-center gap-2"><input v-model="config.account_mode" type="radio" value="all">{{ t('modeltrace.all') }}</label>
        <label class="flex items-center gap-2"><input v-model="config.account_mode" type="radio" value="selected">{{ t('modeltrace.selected') }}</label>
      </div>
      <div v-if="config.account_mode === 'selected'" class="space-y-2">
        <div class="flex flex-wrap items-center gap-2">
          <input v-model="search" class="input max-w-xs" :placeholder="t('modeltrace.search')" :aria-label="t('modeltrace.search')">
          <button type="button" class="btn btn-secondary text-xs" @click="selectAll">{{ t('modeltrace.selectAll') }}</button>
          <button type="button" class="btn btn-secondary text-xs" @click="config.account_ids = []">{{ t('modeltrace.clear') }}</button>
        </div>
        <div class="grid max-h-48 gap-2 overflow-auto rounded-lg border border-gray-200 p-3 text-sm dark:border-gray-700 sm:grid-cols-2 lg:grid-cols-3">
          <label v-for="account in filtered" :key="account.id" class="flex items-center gap-2">
            <input v-model="config.account_ids" type="checkbox" :value="account.id">{{ account.name }} <span class="text-xs text-gray-400">#{{ account.id }}</span>
          </label>
          <span v-if="!accounts.length" class="text-gray-500">{{ t('modeltrace.empty') }}</span>
        </div>
      </div>
      <div class="grid gap-4 sm:grid-cols-2">
        <label class="space-y-1 text-sm"><span>{{ t('modeltrace.interval') }}</span><input v-model.number="config.interval_minutes" class="input" type="number" min="10" max="525600" step="1"></label>
        <label class="space-y-1 text-sm"><span>{{ t('modeltrace.concurrency') }}</span><input v-model.number="config.concurrency" class="input" type="number" min="1" max="50" step="1"></label>
      </div>
      <fieldset v-for="protocol in protocols" :key="protocol" class="space-y-2 rounded-lg border border-gray-200 p-3 dark:border-gray-700">
        <legend class="px-1 text-sm font-medium">{{ protocol === 'codex' ? 'Codex' : 'BPS' }}</legend>
        <label class="flex items-center gap-2 text-sm"><input type="checkbox" :checked="config.targets.some(t => t.protocol === protocol)" @change="toggleProtocol(protocol, ($event.target as HTMLInputElement).checked)">{{ t('modeltrace.enabledProtocol', { protocol }) }}</label>
        <template v-for="(target, index) in config.targets" :key="targetKey(target)">
          <div v-if="target.protocol === protocol" class="space-y-1">
            <div class="flex flex-wrap items-end gap-2">
              <label class="min-w-40 flex-1 text-xs"><span>{{ t('modeltrace.request') }}</span><input v-model="target.model" class="input mt-1" maxlength="256" :placeholder="t('modeltrace.request')"></label>
              <label class="min-w-40 flex-1 text-xs"><span>{{ t('modeltrace.expected') }}</span><input v-model="target.expected_model" class="input mt-1" maxlength="256" :placeholder="target.model || t('modeltrace.expected')"></label>
              <button type="button" class="btn btn-secondary" @click="config.targets.splice(index, 1)">{{ t('modeltrace.remove') }}</button>
            </div>
            <p v-if="(target.expected_model.trim() || target.model.trim()) && !candidates.includes(target.expected_model.trim() || target.model.trim())" class="text-xs text-amber-600 dark:text-amber-400">{{ t('modeltrace.unknownModel') }}</p>
          </div>
        </template>
        <button v-if="config.targets.some(t => t.protocol === protocol)" type="button" class="btn btn-secondary text-xs" @click="config.targets.push({ protocol, model: '', expected_model: '' })">{{ t('modeltrace.add') }}</button>
      </fieldset>
      <p class="text-xs text-gray-500">{{ t('modeltrace.bank') }}</p>
      <div class="flex flex-wrap items-center gap-3">
        <button type="button" class="btn btn-primary" :disabled="busy" @click="save">{{ t('modeltrace.save') }}</button>
        <button type="button" class="btn btn-secondary" :disabled="busy || dirty || !config.enabled" @click="run">{{ t('modeltrace.run') }}</button>
        <span v-if="dirty" class="text-xs text-gray-500">{{ t('modeltrace.dirty') }}</span>
      </div>
    </div>
  </section>
</template>
