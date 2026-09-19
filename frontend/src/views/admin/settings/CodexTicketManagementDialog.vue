<script setup lang="ts">
import { ref } from 'vue'
import { useI18n } from 'vue-i18n'
import BaseDialog from '@/components/common/BaseDialog.vue'
import CodexTicketManagement from './CodexTicketManagement.vue'

const { t } = useI18n()
const show = ref(false)
</script>

<template>
  <div>
    <button
      type="button"
      class="btn btn-secondary"
      data-testid="open-ticket-management"
      aria-haspopup="dialog"
      @click="show = true"
    >
      {{ t('admin.settings.gatewayForwarding.ticketManagement.open') }}
    </button>
    <BaseDialog
      :show="show"
      :title="t('admin.settings.gatewayForwarding.ticketManagement.open')"
      width="extra-wide"
      :close-on-click-outside="true"
      @close="show = false"
    >
      <!-- 关闭即卸载，停止刷新并取消请求；重新打开时读取最新状态。 -->
      <CodexTicketManagement v-if="show" />
      <template #footer>
        <div class="flex justify-end">
          <button type="button" class="btn btn-secondary" data-testid="close-ticket-management" @click="show = false">
            {{ t('common.close') }}
          </button>
        </div>
      </template>
    </BaseDialog>
  </div>
</template>
