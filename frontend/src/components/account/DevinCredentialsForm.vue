<template>
  <div class="space-y-3 rounded-lg border border-gray-200 p-4 dark:border-dark-600">
    <p class="text-sm font-medium">Devin</p>
    <p class="input-hint">{{ t('admin.accounts.devin.description') }}</p>
    <label class="input-label" for="devin-token">Session token</label>
    <input id="devin-token" v-model="token" type="password" autocomplete="new-password" class="input"
      :placeholder="editing ? t('admin.accounts.devin.keepToken') : 'devin-session-token$…'" />
    <button type="button" class="btn btn-secondary" :disabled="busy" @click="startLogin">{{ t('admin.accounts.devin.login') }}</button>
    <div v-if="authURL" class="space-y-2">
      <a :href="authURL" target="_blank" rel="noopener noreferrer" class="text-primary-600 underline">{{ t('admin.accounts.devin.openLogin') }}</a>
      <p class="input-hint">{{ t('admin.accounts.devin.codeHint') }}</p>
      <input v-model="code" type="password" autocomplete="off" class="input" :placeholder="t('admin.accounts.devin.code')" />
      <button type="button" class="btn btn-secondary" :disabled="busy || !code.trim()" @click="exchange">{{ t('admin.accounts.devin.exchange') }}</button>
    </div>
    <p v-if="error" role="alert" class="text-sm text-red-600">{{ error }}</p>
    <p v-if="received" role="status" class="text-sm text-green-600">{{ t('admin.accounts.devin.received') }}</p>
    <label class="input-label" for="devin-base-url">{{ t('admin.accounts.devin.baseURL') }}</label>
    <input id="devin-base-url" v-model="baseURL" type="url" class="input" placeholder="https://server.codeium.com" />
    <p class="input-hint">{{ t('admin.accounts.devin.billing') }}</p>
  </div>
</template>

<script setup lang="ts">
import { onBeforeUnmount, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { apiClient } from '@/api/client'

const props = defineProps<{ proxyId?: number | null; editing?: boolean }>()
const token = defineModel<string>('token', { required: true })
const baseURL = defineModel<string>('baseUrl', { required: true })
const { t } = useI18n()
const busy = ref(false)
const authURL = ref('')
const sessionID = ref('')
const code = ref('')
const error = ref('')
const received = ref(false)
let generation = 0
function clearLogin() {
  generation++
  authURL.value = sessionID.value = code.value = error.value = ''
  received.value = busy.value = false
}
watch(() => props.proxyId, clearLogin)
onBeforeUnmount(clearLogin)
async function startLogin() {
  clearLogin()
  const current = generation
  busy.value = true
  try {
    const { data } = await apiClient.post<{ auth_url: string; session_id: string }>('/admin/devin/oauth/auth-url', { proxy_id: props.proxyId || undefined })
    if (current !== generation) return
    authURL.value = data.auth_url
    sessionID.value = data.session_id
  } catch {
    if (current === generation) error.value = t('admin.accounts.devin.failed')
  } finally {
    if (current === generation) busy.value = false
  }
}
async function exchange() {
  const current = generation
  busy.value = true
  error.value = ''
  try {
    const { data } = await apiClient.post<{ session_token: string }>('/admin/devin/oauth/exchange-code', { session_id: sessionID.value, code: code.value.trim() })
    if (current !== generation) return
    token.value = data.session_token
    clearLogin()
    received.value = true
  } catch {
    if (current === generation) {
      clearLogin()
      error.value = t('admin.accounts.devin.failed')
    }
  } finally {
    if (current === generation) busy.value = false
  }
}
</script>
