<template>
  <div class="card" data-testid="openai-image-priority-accounts">
    <div class="border-b border-gray-100 px-6 py-4 dark:border-dark-700">
      <h2 class="text-lg font-semibold text-gray-900 dark:text-white">
        {{ t("admin.settings.openaiImagePriority.title") }}
      </h2>
      <p class="mt-1 text-sm text-gray-500 dark:text-gray-400">
        {{ t("admin.settings.openaiImagePriority.description") }}
      </p>
    </div>
    <div class="space-y-4 p-6">
      <div v-if="loading" class="flex items-center gap-2 text-gray-500">
        <div
          class="h-4 w-4 animate-spin rounded-full border-b-2 border-primary-600"
        ></div>
        {{ t("common.loading") }}
      </div>

      <template v-else>
        <!-- 已选账号 -->
        <p
          v-if="selected.length === 0"
          class="text-sm text-gray-500 dark:text-gray-400"
          data-testid="openai-image-priority-empty"
        >
          {{ t("admin.settings.openaiImagePriority.empty") }}
        </p>
        <ul
          v-else
          class="divide-y divide-gray-100 rounded-lg border border-gray-100 dark:divide-dark-700 dark:border-dark-700"
          data-testid="openai-image-priority-list"
        >
          <li
            v-for="item in selected"
            :key="item.id"
            class="flex items-center justify-between gap-3 px-3 py-2 text-sm"
          >
            <div class="flex min-w-0 flex-wrap items-center gap-2">
              <span class="truncate font-medium text-gray-900 dark:text-white">
                {{ item.missing ? t("admin.settings.openaiImagePriority.deleted") : item.name }}
              </span>
              <span class="text-xs text-gray-400">#{{ item.id }}</span>
              <span
                v-if="!item.missing && item.status !== 'active'"
                class="rounded bg-red-100 px-1.5 py-0.5 text-xs text-red-700 dark:bg-red-900/30 dark:text-red-300"
              >
                {{ t("admin.settings.openaiImagePriority.statusUnavailable", { status: item.status }) }}
              </span>
              <span
                v-if="!item.missing && !item.schedulable"
                class="rounded bg-gray-100 px-1.5 py-0.5 text-xs text-gray-600 dark:bg-dark-700 dark:text-gray-300"
              >
                {{ t("admin.settings.openaiImagePriority.schedulingOff") }}
              </span>
            </div>
            <button
              type="button"
              class="text-gray-400 hover:text-red-600 dark:hover:text-red-400"
              :aria-label="t('admin.settings.openaiImagePriority.remove')"
              @click="removeAccount(item.id)"
            >
              <Icon name="x" size="sm" />
            </button>
          </li>
        </ul>

        <!-- 搜索 OpenAI 账号 -->
        <div ref="searchContainerRef" class="relative">
          <input
            v-model="searchKeyword"
            type="text"
            class="input text-sm"
            data-testid="openai-image-priority-search"
            :placeholder="t('admin.settings.openaiImagePriority.searchPlaceholder')"
            @input="triggerSearch"
            @focus="onSearchFocus"
          />
          <div
            v-if="showDropdown"
            class="absolute z-50 mt-1 max-h-60 w-full overflow-auto rounded-lg border bg-white shadow-lg dark:border-dark-600 dark:bg-dark-800"
          >
            <p
              v-if="searchResults.length === 0"
              class="px-3 py-2 text-sm text-gray-400"
            >
              {{ t("admin.settings.openaiImagePriority.searchEmpty") }}
            </p>
            <button
              v-for="account in searchResults"
              :key="account.id"
              type="button"
              class="w-full px-3 py-2 text-left text-sm hover:bg-gray-100 disabled:opacity-50 dark:hover:bg-dark-700"
              :disabled="selectedIds.has(account.id)"
              @click="addAccount(account)"
            >
              <span>{{ account.name }}</span>
              <span class="ml-2 text-xs text-gray-400">#{{ account.id }}</span>
              <span
                v-if="!account.schedulable"
                class="ml-2 text-xs text-gray-400"
              >
                {{ t("admin.settings.openaiImagePriority.schedulingOff") }}
              </span>
            </button>
          </div>
        </div>
        <p class="text-xs text-gray-500 dark:text-gray-400">
          {{ t("admin.settings.openaiImagePriority.hint") }}
        </p>

        <div
          class="flex justify-end border-t border-gray-100 pt-4 dark:border-dark-700"
        >
          <button
            type="button"
            class="btn btn-primary btn-sm"
            :disabled="saving"
            data-testid="openai-image-priority-save"
            @click="save"
          >
            {{ saving ? t("common.saving") : t("common.save") }}
          </button>
        </div>
      </template>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from "vue";
import { useI18n } from "vue-i18n";
import Icon from "@/components/icons/Icon.vue";
import { adminAPI } from "@/api/admin";
import type { OpenAIImagePriorityAccounts } from "@/api/admin/accounts";
import { useAppStore } from "@/stores";
import { useKeyedDebouncedSearch } from "@/composables/useKeyedDebouncedSearch";
import { extractApiErrorMessage } from "@/utils/apiError";

interface SelectedAccount {
  id: number;
  name: string;
  status: string;
  schedulable: boolean;
  /** 配置中存在但账号已被删除 */
  missing: boolean;
}

interface SearchAccount {
  id: number;
  name: string;
  status: string;
  schedulable: boolean;
}

const { t } = useI18n();
const appStore = useAppStore();

const loading = ref(true);
const saving = ref(false);
const selected = ref<SelectedAccount[]>([]);
const selectedIds = computed(() => new Set(selected.value.map((item) => item.id)));

const searchKeyword = ref("");
const searchResults = ref<SearchAccount[]>([]);
const showDropdown = ref(false);
const searchContainerRef = ref<HTMLElement | null>(null);

function applyResponse(value: OpenAIImagePriorityAccounts) {
  const byId = new Map(value.accounts.map((account) => [account.id, account]));
  selected.value = value.account_ids.map((id) => {
    const account = byId.get(id);
    return account
      ? { id, name: account.name, status: account.status, schedulable: account.schedulable, missing: false }
      : { id, name: "", status: "", schedulable: false, missing: true };
  });
}

async function load() {
  loading.value = true;
  try {
    applyResponse(await adminAPI.accounts.getOpenAIImagePriorityAccounts());
  } catch (err) {
    appStore.showError(extractApiErrorMessage(err, t("admin.settings.openaiImagePriority.loadFailed")));
  } finally {
    loading.value = false;
  }
}

async function save() {
  saving.value = true;
  try {
    // 已删除的账号随保存一并清理。
    const ids = selected.value.filter((item) => !item.missing).map((item) => item.id);
    applyResponse(await adminAPI.accounts.updateOpenAIImagePriorityAccounts(ids));
    appStore.showSuccess(t("admin.settings.openaiImagePriority.saved"));
  } catch (err) {
    appStore.showError(extractApiErrorMessage(err, t("admin.settings.openaiImagePriority.saveFailed")));
  } finally {
    saving.value = false;
  }
}

const searchRunner = useKeyedDebouncedSearch<SearchAccount[]>({
  delay: 300,
  search: async (keyword, { signal }) => {
    const res = await adminAPI.accounts.list(1, 20, { search: keyword, platform: "openai" }, { signal });
    return res.items.map((account) => ({
      id: account.id,
      name: account.name,
      status: account.status,
      schedulable: account.schedulable,
    }));
  },
  onSuccess: (_key, result) => {
    searchResults.value = result;
  },
  onError: () => {
    searchResults.value = [];
  },
});

function triggerSearch() {
  showDropdown.value = true;
  searchRunner.trigger("openai-image-priority", searchKeyword.value);
}

function onSearchFocus() {
  showDropdown.value = true;
  if (searchResults.value.length === 0) {
    triggerSearch();
  }
}

function addAccount(account: SearchAccount) {
  if (selectedIds.value.has(account.id)) return;
  selected.value = [...selected.value, { ...account, missing: false }];
  searchKeyword.value = "";
  showDropdown.value = false;
}

function removeAccount(id: number) {
  selected.value = selected.value.filter((item) => item.id !== id);
}

function handleDocumentClick(event: MouseEvent) {
  const target = event.target as HTMLElement;
  if (searchContainerRef.value && !searchContainerRef.value.contains(target)) {
    showDropdown.value = false;
  }
}

onMounted(() => {
  document.addEventListener("click", handleDocumentClick);
  load();
});
onUnmounted(() => {
  document.removeEventListener("click", handleDocumentClick);
});
</script>
