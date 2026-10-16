export interface AccountDto {
  id: string;
  alias: string;
  sec_uid?: string;
  uid?: string;
  nickname?: string;
  avatar_url?: string;
  masked_cookie: string;
  status: 'ACTIVE' | 'EXPIRED' | 'DISABLED';
  bark_key_override?: string;
  targets_count: number;
  active_targets_count: number;
  im_history_status?: 'MISSING' | 'EXPIRED' | 'INVALID' | 'AVAILABLE';
  im_history_expires_at?: number | null;
  last_checked_at?: string;
  created_at: string;
  updated_at: string;
}

export interface SparkTarget {
  id: string;
  account_id: string;
  target_sec_uid: string;
  target_uid?: string;
  conversation_id?: string;
  conversation_type?: number; // 1 = 单聊, 2 = 群聊
  target_nickname: string;
  remark_name?: string;
  target_avatar?: string;
  is_enabled: boolean;
  spark_days: number;
  spark_desc?: string;
  is_sparked_today?: boolean | null;
  today_checked_at?: string | null;
  message_template: string;
  last_sent_at?: string;
  last_status?: 'SUCCESS' | 'FAILED';
  last_error?: string;
  created_at: string;
  updated_at: string;
}

export interface SparkLog {
  id: string;
  account_id: string;
  account_alias: string;
  target_id?: string;
  target_nickname?: string;
  action_type: 'CHECK_COOKIE' | 'SEND_SPARK' | 'REFRESH_COOKIE' | 'ACCOUNT_EXECUTION' | 'TEST_SPARK' | 'PRE_SEND_CHECK' | 'POST_SEND_CHECK';
  status: 'SUCCESS' | 'FAILED';
  message: string;
  created_at: string;
}

export interface SystemOverview {
  total_accounts: number;
  active_accounts: number;
  expired_accounts: number;
  total_targets: number;
  active_targets: number;
  today_sparked_count: number;
  next_schedule_time: string;
}

export interface SystemSettings {
  bark_server: string;
  bark_key?: string;
  spark_time: string;
  min_delay_secs: number;
  max_delay_secs: number;
  max_retries: number;
  api_key_masked: string;
  has_bark_key: boolean;
}

export interface DouyinFriend {
  uid: string;
  sec_uid: string;
  nickname: string;
  avatar_url: string;
  spark_days?: number;
  spark_desc?: string;
  is_sparked_today?: boolean;
  target_type?: number; // 1 = 单聊, 2 = 群聊
  conversation_id?: string;
  remark_name?: string;
}
