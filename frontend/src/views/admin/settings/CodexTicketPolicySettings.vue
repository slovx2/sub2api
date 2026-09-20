<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { validCodexTicketPolicy, type CodexTicketPolicy } from '@/utils/codexTicketPolicy'

const props = defineProps<{ modelValue: CodexTicketPolicy }>()
const emit = defineEmits<{ 'update:modelValue': [value: CodexTicketPolicy] }>()
const { t } = useI18n()
const tr = (key: string) => t(`admin.settings.gatewayForwarding.ticketPolicy.${key}`)
const fields = [
  { key: 'ttl_seconds', label: 'ttl', unit: 60, min: 1, max: 1440, step: 'any' },
  { key: 'refresh_before_seconds', label: 'refresh', unit: 60, min: 0, max: 1440, step: 'any' },
  { key: 'harvest_interval_seconds', label: 'interval', unit: 1, min: 1, max: 86400, step: '1' },
  { key: 'max_consecutive_failures', label: 'failures', unit: 1, min: 1, max: 10000, step: '1' }
] as const
const valid = computed(() => validCodexTicketPolicy(props.modelValue))

function update(key: keyof CodexTicketPolicy, event: Event, unit: number) {
  const raw = (event.target as HTMLInputElement).value
  // 空值保留为无效输入，由保存校验拦截，不能悄悄回退默认值。
  const value = raw === '' ? Number.NaN : Number((Number(raw) * unit).toFixed(8))
  emit('update:modelValue', { ...props.modelValue, [key]: value })
}
</script>

<template>
  <div class="space-y-2" data-testid="codex-ticket-policy-settings">
    <div class="grid gap-3 sm:grid-cols-2">
      <label v-for="field in fields" :key="field.key" class="text-sm font-medium">
        {{ tr(field.label) }}
        <input
          :id="`codex-ticket-${field.key}`"
          type="number"
          class="input mt-2 w-full"
          :value="Number.isFinite(modelValue[field.key]) ? modelValue[field.key] / field.unit : ''"
          :min="field.min"
          :max="field.max"
          :step="field.step"
          required
          :aria-invalid="!valid"
          @input="update(field.key, $event, field.unit)"
        />
      </label>
    </div>
    <p class="text-sm text-gray-500">{{ tr('hint') }}</p>
    <p v-if="!valid" role="alert" class="text-sm text-red-600">{{ tr('invalid') }}</p>
  </div>
</template>
