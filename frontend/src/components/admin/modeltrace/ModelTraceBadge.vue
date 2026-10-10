<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import { nextTick, onBeforeUnmount, onMounted, ref, useId } from 'vue'
import type { ModelTraceDetail, ModelTraceSummary } from '@/api/admin/modeltrace'
import ModelTraceHistory from './ModelTraceHistory.vue'

defineProps<{ accountId: number; summary?: ModelTraceSummary }>()
const emit = defineEmits<{ historyOpen: [value: boolean] }>()
const { t } = useI18n()
const tooltipID = useId()
const trigger = ref<HTMLButtonElement>()
const tooltip = ref<HTMLElement>()
const show = ref(false)
const focused = ref(false)
const historyOpen = ref(false)
const now = ref(Date.now())
let clockTimer: ReturnType<typeof setInterval> | undefined
const position = ref({ top: '0px', left: '0px' })
function updatePosition() {
  if (!show.value || !trigger.value || !tooltip.value) return
  const rect = trigger.value.getBoundingClientRect()
  const width = tooltip.value.offsetWidth
  const height = tooltip.value.offsetHeight
  position.value = {
    top: `${rect.top > height + 8 ? rect.top - height - 8 : rect.bottom + 8}px`,
    left: `${Math.max(8, Math.min(rect.left, window.innerWidth - width - 8))}px`,
  }
}
function open() { if (!historyOpen.value) { show.value = true; nextTick(updatePosition) } }
function close() { show.value = false }
function focus() { focused.value = true; open() }
function blur() { focused.value = false; close() }
function openHistory() { close(); historyOpen.value = true; emit('historyOpen', true) }
async function closeHistory() { historyOpen.value = false; emit('historyOpen', false); await nextTick(); trigger.value?.focus() }
function streakLabel(detail: ModelTraceDetail): string {
  if (detail.verdict !== 'matched' || !detail.matched_since) return ''
  const minutes = Math.max(0, Math.floor((now.value - Date.parse(detail.matched_since)) / 60000))
  if (!Number.isFinite(minutes)) return ''
  if (minutes === 0) return t('modeltrace.streakUnderMinute')
  const days = Math.floor(minutes / 1440)
  const hours = Math.floor(minutes % 1440 / 60)
  const rest = minutes % 60
  const duration = [days ? t('modeltrace.days', { n: days }) : '', hours ? t('modeltrace.hours', { n: hours }) : '', t('modeltrace.minutes', { n: rest })].filter(Boolean).join(' ')
  return t('modeltrace.streak', { duration })
}
function leave(event: MouseEvent) {
  const next = event.relatedTarget
  if (focused.value || next instanceof Node && (tooltip.value?.contains(next) || trigger.value?.contains(next))) return
  close()
}
onMounted(() => {
  clockTimer = setInterval(() => { now.value = Date.now(); nextTick(updatePosition) }, 60000)
  window.addEventListener('resize', updatePosition)
  window.addEventListener('scroll', updatePosition, true)
})
onBeforeUnmount(() => {
  if (historyOpen.value) emit('historyOpen', false)
  clearInterval(clockTimer)
  window.removeEventListener('resize', updatePosition)
  window.removeEventListener('scroll', updatePosition, true)
})
function resultLabel(detail: ModelTraceDetail): string {
  if (detail.status === 'pending') return t('modeltrace.pending')
  if (detail.status !== 'success') return `${t('modeltrace.failed')} · ${detail.error || '—'}`
  if (detail.verdict !== 'unknown') return detail.prediction || '—'
  return `${detail.prediction} ${(detail.probability * 100).toFixed(1)}% · ${t('modeltrace.uncertain')}`
}
function timestamp(value: string): string { return value && !value.startsWith('0001-') ? new Date(value).toLocaleString() : '' }
</script>

<template>
  <span v-if="summary" class="inline-flex self-start">
      <button ref="trigger" type="button" class="inline-flex gap-1 text-[11px] leading-4" aria-label="ModelTrace" aria-haspopup="dialog" :aria-describedby="show ? tooltipID : undefined" @click.stop="openHistory" @mouseenter="open" @mouseleave="leave" @focusin="focus" @focusout="blur" @keydown.esc="close">
        <span class="text-green-600 dark:text-green-400">{{ t('modeltrace.matched') }} {{ summary.matched }}</span>
        <span class="text-gray-400">·</span>
        <span class="text-red-600 dark:text-red-400">{{ t('modeltrace.mismatched') }} {{ summary.mismatched }}</span>
      </button>
    <Teleport to="body">
    <div v-show="show" :id="tooltipID" ref="tooltip" role="tooltip" :style="position" class="fixed z-[99999] w-max max-w-[min(560px,90vw)] rounded-lg bg-gray-900 p-3 text-xs leading-relaxed text-white shadow-xl before:absolute before:inset-x-0 before:-inset-y-2 before:-z-10 dark:bg-gray-800" @mouseleave="leave">
    <div class="max-h-80 space-y-2 overflow-y-auto">
      <div class="flex gap-2 font-medium"><span>ModelTrace</span><span v-if="!summary.enabled" class="text-gray-300">{{ t('modeltrace.disabled') }}</span><span v-else-if="summary.running">{{ t('modeltrace.running') }}</span><span v-if="summary.auto_schedule" class="text-amber-300">{{ t('modeltrace.autoScheduled') }}</span></div>
      <div v-for="detail in summary.details" :key="`${detail.protocol}/${detail.model}`" class="border-t border-white/15 pt-2">
        <div class="break-all">{{ detail.protocol }} / {{ detail.model }} → {{ detail.expected_model }}</div>
        <div :class="detail.verdict === 'matched' ? 'text-green-300' : detail.verdict === 'mismatched' ? 'text-red-300' : 'text-gray-300'">{{ resultLabel(detail) }}</div>
        <div v-if="summary.enabled && streakLabel(detail)" class="text-green-300">{{ streakLabel(detail) }}</div>
        <div v-if="detail.upstream_model && detail.upstream_model !== detail.model" class="text-gray-400">{{ t('modeltrace.actual') }}: {{ detail.upstream_model }}</div>
        <div class="text-[10px] text-gray-400">{{ timestamp(detail.finished_at) }}</div>
      </div>
    </div>
    </div>
    </Teleport>
    <ModelTraceHistory :show="historyOpen" :account-id="accountId" @close="closeHistory" />
  </span>
</template>
