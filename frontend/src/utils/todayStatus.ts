import type { AccountDto, SparkTarget } from '../types';

export function cstDate(value?: string | Date | null): string {
  if (!value) return '';
  const date = typeof value === 'string' ? new Date(value) : value;
  if (Number.isNaN(date.getTime())) return '';
  return new Intl.DateTimeFormat('sv-SE', { timeZone: 'Asia/Shanghai' }).format(date);
}

export function getImHistoryBlocker(account?: AccountDto, now = new Date()) {
  const status = account?.im_history_status;
  if (status === 'MISSING') return '缺少 IM 凭证';
  if (status === 'INVALID') return 'IM 凭证无效';
  if (status === 'EXPIRED' || (status === 'AVAILABLE'
    && (!Number.isFinite(account?.im_history_expires_at)
      || now.getTime() >= (account!.im_history_expires_at! + 1) * 1000))) return 'IM 凭证已过期';
  return '';
}

// 账号 IM 缓存是否过期不改变目标已经确认的今日事实，也不代表目标发送失败。
export function getTodaySparkStatus(target: SparkTarget, now = new Date(), _account?: AccountDto) {
  const today = cstDate(now);
  const lastToday = cstDate(target.last_sent_at) === today
    && new Date(target.last_sent_at || '').getTime() <= now.getTime();
  const checkedToday = cstDate(target.today_checked_at) === today
    && new Date(target.today_checked_at || '').getTime() <= now.getTime();
  const successColor = 'bg-emerald-100 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-400 border-emerald-300 dark:border-emerald-800';
  if (lastToday && target.last_status === 'SUCCESS') {
    return { code: 'SUCCESS', label: '今日已续 (系统已发)', color: successColor };
  }
  if (checkedToday && target.is_sparked_today === true) {
    return { code: 'SUCCESS', label: '今日已续 (我已发消息)', color: successColor };
  }
  if (lastToday && target.last_status === 'FAILED') {
    return { code: 'FAILED', label: '今日发送失败', color: 'bg-rose-100 dark:bg-rose-950/40 text-rose-700 dark:text-rose-400 border-rose-300 dark:border-rose-800' };
  }
  if (checkedToday && target.is_sparked_today === false) {
    return { code: 'PENDING', label: '今日未续 (待续火)', color: 'bg-amber-100 dark:bg-amber-950/40 text-amber-700 dark:text-amber-400 border-amber-300 dark:border-amber-800' };
  }
  return { code: 'UNKNOWN', label: '今日未确认', color: 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 border-slate-300 dark:border-slate-700' };
}
