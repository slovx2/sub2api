<template>
  <span
    v-if="disabledAt"
    data-test="excel-bps-403-badge"
    class="mt-1 inline-flex items-center self-start rounded bg-amber-400 px-1.5 py-0.5 text-[11px] font-semibold leading-4 text-amber-950 ring-1 ring-amber-500"
    :title="t('admin.accounts.openai.excelBPS403BadgeTooltip', { time: formatDateTime(disabledAt) })"
  >
    {{ t('admin.accounts.openai.excelBPS403Badge') }}
  </span>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import type { Account } from '@/types'
import { formatDateTime } from '@/utils/format'

const props = defineProps<{
  account: Account
}>()

const { t } = useI18n()

// 后端在 Excel / BPS 因 403 自动停止调度时写入该时间；
// 人工重新打开调度开关后标记被清除，标签随之消失。
const disabledAt = computed(() => {
  const { platform, type, extra, schedulable } = props.account
  if (platform !== 'openai' || type !== 'oauth' || !extra || schedulable !== false) return null
  const value = extra.openai_excel_bps_403_disabled_at
  if (typeof value !== 'string') return null
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? null : date
})
</script>
