<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import BaseDialog from '@/components/common/BaseDialog.vue'
import { getModelTraceHistory, type ModelTraceHistoryEntry, type ProbeProtocol } from '@/api/admin/modeltrace'

const props = defineProps<{ show: boolean; accountId: number }>()
const emit = defineEmits<{ close: [] }>()
const { t } = useI18n()
const protocol = ref<'' | ProbeProtocol>('')
const model = ref('')
const items = ref<ModelTraceHistoryEntry[]>([])
const cursor = ref<string>()
const busy = ref(false)
const failed = ref(false)
let requestGeneration = 0
let applied: { protocol?: ProbeProtocol; model?: string } = {}
const hasMore = computed(() => !!cursor.value)

async function load(more = false) {
  const generation = ++requestGeneration
  busy.value = true
  failed.value = false
  if (!more) {
    items.value = []; cursor.value = undefined
    applied = { protocol: protocol.value || undefined, model: model.value.trim() || undefined }
  }
  try {
    const page = await getModelTraceHistory({ account_id: props.accountId, ...applied, cursor: more ? cursor.value : undefined })
    if (generation !== requestGeneration) return
    items.value = more ? [...items.value, ...page.items] : page.items
    cursor.value = page.next_cursor
  } catch {
    if (generation === requestGeneration) failed.value = true
  } finally {
    if (generation === requestGeneration) busy.value = false
  }
}
watch(() => [props.show, props.accountId] as const, ([show]) => {
  if (show) { protocol.value = ''; model.value = ''; void load() }
  else { requestGeneration++; busy.value = false }
}, { immediate: true })
</script>

<template>
  <BaseDialog :show="show" :title="t('modeltrace.history')" width="wide" @close="emit('close')">
    <p class="mb-3 text-xs text-gray-500">{{ t('modeltrace.historyHint') }}</p>
    <form class="mb-4 flex flex-wrap gap-2" @submit.prevent="load()">
      <select v-model="protocol" class="input w-auto" :aria-label="t('modeltrace.protocol')">
        <option value="">{{ t('modeltrace.allProtocols') }}</option>
        <option value="bps">BPS</option><option value="codex">Codex</option>
      </select>
      <input v-model="model" class="input max-w-xs" maxlength="256" :placeholder="t('modeltrace.request')" :aria-label="t('modeltrace.request')">
      <button type="submit" class="btn btn-secondary" :disabled="busy">{{ t('modeltrace.filter') }}</button>
    </form>
    <div v-if="failed" role="alert" class="mb-3 text-sm text-red-600">
      {{ t('modeltrace.historyError') }}
      <button class="ml-2 underline" type="button" @click="load(items.length > 0)">{{ t('modeltrace.retry') }}</button>
    </div>
    <div class="overflow-x-auto">
      <table v-if="items.length" class="w-full text-left text-xs">
        <thead><tr class="border-b dark:border-gray-700">
          <th class="p-2">{{ t('modeltrace.time') }}</th><th class="p-2">{{ t('modeltrace.protocol') }}</th>
          <th class="p-2">{{ t('modeltrace.request') }}</th><th class="p-2">{{ t('modeltrace.historyExpected') }}</th><th class="p-2">{{ t('modeltrace.result') }}</th>
        </tr></thead>
        <tbody>
          <tr v-for="item in items" :key="item.id" class="border-b align-top dark:border-gray-700">
            <td class="whitespace-nowrap p-2">{{ new Date(item.finished_at).toLocaleString() }}</td>
            <td class="p-2">{{ item.protocol === 'bps' ? 'BPS' : 'Codex' }}</td>
            <td class="break-all p-2">{{ item.model }}</td><td class="break-all p-2">{{ item.expected_model }}</td>
            <td class="p-2" :class="item.verdict === 'matched' ? 'text-green-600' : item.verdict === 'mismatched' ? 'text-red-600' : 'text-gray-500'">
              <template v-if="item.status === 'success'">
                {{ t(`modeltrace.${item.verdict === 'unknown' ? 'uncertain' : item.verdict}`) }} · {{ item.prediction }} {{ (item.probability * 100).toFixed(1) }}%
              </template>
              <template v-else>{{ t('modeltrace.failed') }} · {{ item.error || '—' }}</template>
            </td>
          </tr>
        </tbody>
      </table>
      <p v-else-if="!busy && !failed" class="py-6 text-center text-sm text-gray-500">{{ t('modeltrace.noHistory') }}</p>
    </div>
    <p v-if="busy" class="mt-3 text-sm text-gray-500" role="status">{{ t('modeltrace.loading') }}</p>
    <button v-if="hasMore && !failed" type="button" class="btn btn-secondary mt-4" :disabled="busy" @click="load(true)">{{ t('modeltrace.loadMore') }}</button>
  </BaseDialog>
</template>
