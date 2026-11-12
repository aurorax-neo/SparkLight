import {
  AccountDto,
  DouyinFriend,
  SparkLog,
  SparkTarget,
  SparkTemplateItem,
  SystemOverview,
  SystemSettings,
  TemplatePreviewResult,
  TemplatesConfigDto,
} from '../types';

export interface AccountLoginStart {
  login_id: string;
  account_id: string;
  qrcode: string;
  expires_in: number;
}

export interface PhoneLoginStart {
  login_id: string;
  account_id: string;
  mobile_masked: string;
  expires_in: number;
}

export interface NativeLoginDone {
  login_id?: string;
  account_id: string;
  uid?: string;
  nickname?: string;
  status: string;
  done: boolean;
  native_ready?: boolean;
  web_ready?: boolean;
  identity_ready?: boolean;
  guard_ready?: boolean;
  challenge?: AccountLoginChallenge;
}

export interface AccountLoginStatus {
  login_id: string;
  account_id?: string;
  uid?: string;
  nickname?: string;
  status: 'new' | 'loading' | 'scanned' | 'verifying' | 'confirmed' | 'done' | 'expired' | 'refused' | 'failed' | 'canceled';
  done: boolean;
  expires_in?: number;
  challenge_url?: string;
  challenge?: AccountLoginChallenge;
  native_ready?: boolean;
  web_ready?: boolean;
  identity_ready?: boolean;
  guard_ready?: boolean;
}

export type AccountLoginChallenge =
  | { kind: 'web'; url: string }
  | {
      kind: 'two_step';
      masked_mobile?: string;
      ways: AccountLoginVerifyWay[];
      profile_name?: string;
      avatar_url?: string;
      ticket_ready?: boolean;
      scene_description?: string;
    };

export interface AccountLoginVerifyWay {
  kind: 'mobile_sms_verify' | 'mobile_up_sms_verify' | 'pwd_verify' | 'face_verify' | string;
  label: string;
  masked_mobile?: string;
  supported: boolean;
  description?: string;
}

export interface AccountLoginDelivery {
  kind: string;
  sms_content?: string;
  channel_mobile?: string;
  qrcode?: string;
}

export interface NativeSessionImportResult {
  account_id: string;
  alias: string;
  uid: string;
  native_ready: boolean;
  web_ready: boolean;
  sid_expires_at: number;
}

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
  runAll: (force_resend = false) =>
    request<{ data: any; message: string }>('/api/v1/system/run-all', {
      method: 'POST',
      body: JSON.stringify({ force_resend }),
    }),

  // Accounts
  getAccounts: () => request<{ data: AccountDto[] }>('/api/v1/accounts').then((r) => r.data),
  updateAccount: (id: string, payload: { alias?: string; status?: string; bark_key_override?: string }) =>
    request<{ message: string }>(`/api/v1/accounts/${id}`, {
      method: 'PUT',
      body: JSON.stringify(payload),
    }),
  deleteAccount: (id: string) =>
    request<{ message: string }>(`/api/v1/accounts/${id}`, {
      method: 'DELETE',
    }),
  checkAccount: (id: string) =>
    request<{
      data: {
        is_valid: boolean;
        confirmed: boolean;
        check_state: 'valid' | 'expired' | 'unconfirmed';
        status: string;
        nickname?: string | null;
        avatar_url?: string | null;
        last_checked_at?: string | null;
      };
      message: string;
    }>(`/api/v1/accounts/${id}/check`, {
      method: 'POST',
    }),
  // App 原生二维码登录：二维码和登录状态均由 Rust 服务端直接对接抖音 Passport。
  startAccountLogin: (payload: { alias?: string; account_id?: string }) =>
    request<{ data: AccountLoginStart; message: string }>(
      '/api/v1/accounts/login/start',
      {
        method: 'POST',
        body: JSON.stringify(payload),
      },
    ),
  getAccountLoginStatus: (loginId: string) =>
    request<{ data: AccountLoginStatus; message: string }>(
      `/api/v1/accounts/login/${loginId}`,
    ),
  sendAccountLoginVerificationCode: (loginId: string, way: string) =>
    request<{ data: AccountLoginStatus & { delivery?: AccountLoginDelivery }; message: string }>(
      `/api/v1/accounts/login/${loginId}/verify/send`,
      {
        method: 'POST',
        body: JSON.stringify({ way }),
      },
    ),
  prepareAccountLoginUpSms: (loginId: string, way: string) =>
    request<{ data: AccountLoginStatus & { delivery: AccountLoginDelivery }; message: string }>(
      `/api/v1/accounts/login/${loginId}/verify/up-sms`,
      {
        method: 'POST',
        body: JSON.stringify({ way }),
      },
    ),
  submitAccountLoginVerification: (
    loginId: string,
    payload: { way: string; code?: string; password?: string },
  ) =>
    request<{ data: AccountLoginStatus; message: string }>(
      `/api/v1/accounts/login/${loginId}/verify/submit`,
      {
        method: 'POST',
        body: JSON.stringify(payload),
      },
    ),
  cancelAccountLogin: (loginId: string) =>
    request<{ message: string }>(`/api/v1/accounts/login/${loginId}/cancel`, {
      method: 'POST',
    }),
  startPhoneLogin: (payload: { alias?: string; account_id?: string; mobile: string }) =>
    request<{ data: PhoneLoginStart; message: string }>(
      '/api/v1/accounts/login/phone',
      {
        method: 'POST',
        body: JSON.stringify(payload),
      },
    ),
  verifyPhoneLogin: (loginId: string, code: string) =>
    request<{ data: NativeLoginDone; message: string }>(
      `/api/v1/accounts/login/phone/${loginId}/verify`,
      {
        method: 'POST',
        body: JSON.stringify({ code }),
      },
    ),
  passwordLogin: (payload: { alias?: string; account_id?: string; mobile: string; password: string }) =>
    request<{ data: NativeLoginDone; message: string }>(
      '/api/v1/accounts/login/password',
      {
        method: 'POST',
        body: JSON.stringify(payload),
      },
    ),
  importNativeSession: (session: unknown, skipWebBootstrap = false) =>
    request<{ data: NativeSessionImportResult; message: string; warning?: string | null }>(
      '/api/v1/accounts/native-import',
      {
        method: 'POST',
        body: JSON.stringify({ session, skip_web_bootstrap: skipWebBootstrap }),
      },
    ),
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
  getTemplates: () =>
    request<{ data: TemplatesConfigDto }>('/api/v1/targets/templates').then((r) => r.data),
  saveTemplates: (payload: {
    default_template?: string;
    custom_templates?: SparkTemplateItem[];
  }) =>
    request<{ data: TemplatesConfigDto }>('/api/v1/targets/templates', {
      method: 'PUT',
      body: JSON.stringify(payload),
    }).then((r) => r.data),
  previewTemplate: (payload: {
    template: string;
    target_name?: string;
    spark_days?: number;
  }) =>
    request<{ data: TemplatePreviewResult; message: string }>(
      '/api/v1/targets/templates/preview',
      {
        method: 'POST',
        body: JSON.stringify(payload),
      },
    ).then((r) => r.data),
  applyTemplate: (payload: {
    template: string;
    account_id?: string;
    target_ids?: string[];
    set_as_default?: boolean;
  }) =>
    request<{ data: { updated_count: number; template: string }; message: string }>(
      '/api/v1/targets/templates/apply',
      {
        method: 'POST',
        body: JSON.stringify(payload),
      },
    ),

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
