import { AccountDto, DouyinFriend, SparkLog, SparkTarget, SystemOverview, SystemSettings } from '../types';

let onAuthErrorCallback: (() => void) | null = null;

export function setOnAuthError(cb: () => void) {
  onAuthErrorCallback = cb;
}

export function getStoredApiKey(): string {
  return localStorage.getItem('sparklight_api_key') || '';
}

export function setStoredApiKey(key: string) {
  localStorage.setItem('sparklight_api_key', key.trim());
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const apiKey = getStoredApiKey();
  const headers = new Headers(options.headers || {});

  headers.set('Content-Type', 'application/json');
  if (apiKey) {
    headers.set('X-API-Key', apiKey);
  }

  const res = await fetch(path, {
    ...options,
    headers,
  });

  if (res.status === 401) {
    if (onAuthErrorCallback) {
      onAuthErrorCallback();
    }
    throw new Error('未授权: API Key 无效或未填写');
  }

  const text = await res.text();
  let data: any = {};
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      throw new Error(text.replace(/\s+/g, ' ').slice(0, 180) || `请求失败 (${res.status})`);
    }
  }
  if (!res.ok || (data.code !== undefined && data.code !== 200)) {
    throw new Error(data.message || `请求失败 (${res.status})`);
  }

  return data;
}

export const api = {
  // System
  getHealth: () => request<{ status: string }>('/api/v1/system/health'),
  getOverview: () => request<{ data: SystemOverview }>('/api/v1/system/overview').then((r) => r.data),
  launchBrave: (url?: string) =>
    request<{ message: string }>('/api/v1/system/launch-brave', {
      method: 'POST',
      body: JSON.stringify({ url }),
    }),
  runAll: (force_resend = false) =>
    request<{ data: any; message: string }>('/api/v1/system/run-all', {
      method: 'POST',
      body: JSON.stringify({ force_resend }),
    }),

  // Accounts
  getAccounts: () => request<{ data: AccountDto[] }>('/api/v1/accounts').then((r) => r.data),
  createAccount: (payload: { alias: string; cookie: string; bark_key_override?: string }) =>
    request<{ data: any; message: string }>('/api/v1/accounts', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  updateAccount: (id: string, payload: { alias?: string; cookie?: string; status?: string; bark_key_override?: string }) =>
    request<{ message: string }>(`/api/v1/accounts/${id}`, {
      method: 'PUT',
      body: JSON.stringify(payload),
    }),
  deleteAccount: (id: string) =>
    request<{ message: string }>(`/api/v1/accounts/${id}`, {
      method: 'DELETE',
    }),
  checkAccount: (id: string) =>
    request<{ data: any; message: string }>(`/api/v1/accounts/${id}/check`, {
      method: 'POST',
    }),
  syncBrowserCookie: (id: string, cookie: string) =>
    request<{ message: string }>(`/api/v1/accounts/${id}/sync-cookie`, {
      method: 'POST',
      body: JSON.stringify({ cookie }),
    }),
  getApiKey: () => getStoredApiKey(),
  syncFriends: (id: string) =>
    request<{ data: DouyinFriend[]; message: string }>(`/api/v1/accounts/${id}/sync-friends`, {
      method: 'POST',
    }).then((r) => r.data),
  syncFriendsWithStatus: (id: string) =>
    request<{ data: DouyinFriend[]; message: string; today_status?: { confirmed: number; unconfirmed: number } }>(`/api/v1/accounts/${id}/sync-friends`, {
      method: 'POST',
    }),
  runAccount: (id: string) =>
    request<{ data: any; message: string }>(`/api/v1/accounts/${id}/run`, {
      method: 'POST',
    }),

  // Targets
  getTargets: (accountId?: string) => {
    const q = accountId ? `?account_id=${encodeURIComponent(accountId)}` : '';
    return request<{ data: SparkTarget[] }>(`/api/v1/targets${q}`).then((r) => r.data);
  },
  createTarget: (payload: {
    account_id: string;
    target_sec_uid: string;
    target_uid?: string;
    conversation_id?: string;
    conversation_type?: number;
    target_nickname: string;
    remark_name?: string;
    target_avatar?: string;
    spark_days?: number;
    spark_desc?: string;
    is_sparked_today?: boolean;
    message_template?: string;
  }) =>
    request<{ data: SparkTarget; message: string }>('/api/v1/targets', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  batchCreateTargets: (account_id: string, targets: any[]) =>
    request<{ added_count: number; message: string }>('/api/v1/targets/batch', {
      method: 'POST',
      body: JSON.stringify({ account_id, targets }),
    }),
  updateTarget: (
    id: string,
    payload: { is_enabled?: boolean; target_nickname?: string; remark_name?: string; spark_days?: number; spark_desc?: string; is_sparked_today?: boolean; conversation_type?: number; message_template?: string }
  ) =>
    request<{ message: string }>(`/api/v1/targets/${id}`, {
      method: 'PUT',
      body: JSON.stringify(payload),
    }),
  deleteTarget: (id: string) =>
    request<{ message: string }>(`/api/v1/targets/${id}`, {
      method: 'DELETE',
    }),
  getTarget: (id: string) => request<{ data: SparkTarget }>(`/api/v1/targets/${id}`).then((r) => r.data),
  refreshTarget: (id: string) => request<{ data: SparkTarget; confirmed: boolean; message: string; im_history_status?: AccountDto['im_history_status']; im_history_expires_at?: number | null }>(`/api/v1/targets/${id}/refresh`, { method: 'POST' }),
  testTarget: (id: string) =>
    request<{ data: any; message: string }>(`/api/v1/targets/${id}/test`, {
      method: 'POST',
    }),

  // Logs
  getLogs: (params: { limit?: number; offset?: number; account_id?: string; status?: string } = {}) => {
    const query = new URLSearchParams();
    if (params.limit) query.set('limit', String(params.limit));
    if (params.offset) query.set('offset', String(params.offset));
    if (params.account_id) query.set('account_id', params.account_id);
    if (params.status) query.set('status', params.status);
    return request<{ data: { items: SparkLog[]; total: number; limit: number; offset: number } }>(
      `/api/v1/logs?${query.toString()}`
    ).then((r) => r.data);
  },

  // Settings
  getSettings: () => request<{ data: SystemSettings }>('/api/v1/settings').then((r) => r.data),
  updateSettings: (payload: Partial<SystemSettings>) =>
    request<{ message: string }>('/api/v1/settings', {
      method: 'PUT',
      body: JSON.stringify(payload),
    }),
  testBark: (server?: string, key?: string) =>
    request<{ message: string }>('/api/v1/settings/test-bark', {
      method: 'POST',
      body: JSON.stringify({ server, key }),
    }),
};
