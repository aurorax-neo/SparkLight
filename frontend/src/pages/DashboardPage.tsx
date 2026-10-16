import React, { useEffect, useState } from 'react';
import {
  Users,
  Sparkles,
  Flame,
  Clock,
  CheckCircle2,
  AlertTriangle,
  ArrowRight,
  RefreshCw,
  Loader2,
} from 'lucide-react';
import { api } from '../api/client';
import { AccountDto, SparkLog, SystemOverview } from '../types';
import { TabType } from '../components/Navbar';
import { accountDisplayName } from '../utils/displayName';

interface Props {
  active?: boolean;
  onNavigate: (tab: TabType) => void;
  refreshTrigger: number;
}

export const DashboardPage: React.FC<Props> = ({ active = true, onNavigate, refreshTrigger }) => {
  const [overview, setOverview] = useState<SystemOverview | null>(null);
  const [accounts, setAccounts] = useState<AccountDto[]>([]);
  const [recentLogs, setRecentLogs] = useState<SparkLog[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);

  const loadData = async () => {
    try {
      const [ovData, accData, logsData] = await Promise.all([
        api.getOverview().catch(() => null),
        api.getAccounts().catch(() => []),
        api.getLogs({ limit: 5 }).catch(() => ({ items: [], total: 0 })),
      ]);

      if (ovData) setOverview(ovData);
      setAccounts(accData);
      setRecentLogs(logsData.items);
    } catch (e) {
      console.error(e);
    } finally {
      setIsLoading(false);
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    if (active) loadData();
  }, [active, refreshTrigger]);

  const handleRefresh = () => {
    setIsRefreshing(true);
    loadData();
  };

  if (isLoading) {
    return (
      <div className="space-y-6" aria-busy="true">
        <div>
          <h1 className="text-xl font-bold text-slate-900 dark:text-slate-100">工作台概览</h1>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">监控所有已隔离账号凭证状态与每日续火花进度</p>
        </div>
        <div className="flex items-center justify-center min-h-[50vh]" role="status" aria-label="加载概览">
          <Loader2 className="w-8 h-8 text-orange-500 animate-spin" />
        </div>
      </div>
    );
  }

  const statCards = [
    {
      title: '多账号管理',
      value: overview?.total_accounts ?? 0,
      sub: `${overview?.active_accounts ?? 0} 正常 · ${overview?.expired_accounts ?? 0} 失效`,
      icon: Users,
      color: 'from-blue-500 to-indigo-600',
      actionTab: 'accounts' as TabType,
    },
    {
      title: '续火花对象',
      value: overview?.total_targets ?? 0,
      sub: `${overview?.active_targets ?? 0} 个监控中`,
      icon: Sparkles,
      color: 'from-amber-500 to-orange-600',
      actionTab: 'targets' as TabType,
    },
    {
      title: '今日成功续火花',
      value: overview?.today_sparked_count ?? 0,
      sub: '今日已完成互动对象',
      icon: Flame,
      color: 'from-orange-500 to-rose-600',
      actionTab: 'logs' as TabType,
    },
    {
      title: '定时调度策略',
      value: overview?.next_schedule_time ?? '09:30',
      sub: '每日自动全量执行',
      icon: Clock,
      color: 'from-emerald-500 to-teal-600',
      actionTab: 'settings' as TabType,
    },
  ];

  return (
    <div className="space-y-6">
      {/* Header bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
            工作台概览
          </h1>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            监控所有已隔离账号凭证状态与每日续火花进度
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handleRefresh}
            disabled={isRefreshing}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-xl border border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin' : ''}`} />
            <span>刷新数据</span>
          </button>
        </div>
      </div>

      {/* Metric Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {statCards.map((c, idx) => {
          const Icon = c.icon;
          return (
            <div
              key={idx}
              onClick={() => onNavigate(c.actionTab)}
              className="cursor-pointer group p-5 rounded-2xl bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800/80 hover:border-orange-500/50 dark:hover:border-orange-500/50 shadow-sm transition-all hover:shadow-md"
            >
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-slate-500 dark:text-slate-400">{c.title}</span>
                <div className={`p-2 rounded-xl bg-gradient-to-tr ${c.color} text-white shadow-sm`}>
                  <Icon className="w-4 h-4" />
                </div>
              </div>
              <div className="mt-3 flex items-baseline justify-between">
                <span className="text-2xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
                  {c.value}
                </span>
                <ArrowRight className="w-4 h-4 text-slate-400 group-hover:text-orange-500 transition -translate-x-1 group-hover:translate-x-0" />
              </div>
              <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-1">{c.sub}</p>
            </div>
          );
        })}
      </div>

      {/* Main Split Section */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Account Status Quick View */}
        <div className="lg:col-span-2 rounded-2xl bg-white dark:bg-slate-900 p-5 border border-slate-200/80 dark:border-slate-800/80 shadow-sm">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">账号运行状态</h2>
              <p className="text-xs text-slate-500 dark:text-slate-400">隔离存储与有效性监控</p>
            </div>
            <button
              onClick={() => onNavigate('accounts')}
              className="text-xs font-medium text-orange-600 dark:text-orange-400 hover:underline flex items-center gap-1"
            >
              管理全部账号 <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>

          {accounts.length === 0 ? (
            <div className="text-center py-10 border border-dashed border-slate-200 dark:border-slate-800 rounded-xl">
              <Users className="w-8 h-8 text-slate-400 mx-auto mb-2" />
              <p className="text-xs text-slate-500">暂无录入抖音账号</p>
              <button
                onClick={() => onNavigate('accounts')}
                className="mt-3 px-3 py-1.5 text-xs font-medium bg-orange-500 text-white rounded-lg hover:bg-orange-600"
              >
                立即添加账号
              </button>
            </div>
          ) : (
            <div className="space-y-2.5">
              {accounts.slice(0, 4).map((acc) => {
                const isValid = acc.status === 'ACTIVE';
                return (
                  <div
                    key={acc.id}
                    className="flex items-center justify-between p-3 rounded-xl border border-slate-100 dark:border-slate-800/60 bg-slate-50/50 dark:bg-slate-800/30 hover:bg-slate-50 dark:hover:bg-slate-800/60 transition gap-3 min-w-0"
                  >
                    <div className="flex items-center gap-3 min-w-0 flex-1">
                      {acc.avatar_url ? (
                        <img src={acc.avatar_url} alt="" className="w-9 h-9 rounded-full object-cover shrink-0" />
                      ) : (
                        <div className="w-9 h-9 rounded-full bg-slate-200 dark:bg-slate-700 flex items-center justify-center font-bold text-xs text-slate-600 dark:text-slate-300 shrink-0">
                          {accountDisplayName(acc.nickname, acc.alias).slice(0, 1)}
                        </div>
                      )}
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-semibold text-slate-900 dark:text-slate-100 truncate" title={accountDisplayName(acc.nickname, acc.alias)}>
                            {accountDisplayName(acc.nickname, acc.alias)}
                          </span>
                        </div>
                        <p className="text-[10px] text-slate-400 font-mono mt-0.5 truncate">
                          {acc.masked_cookie ? acc.masked_cookie.slice(0, 32) + '...' : '未配置Cookie'}
                        </p>
                      </div>
                    </div>

                    <div className="flex items-center gap-3 text-right shrink-0">
                      <div>
                        <span
                          className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold ${
                            isValid
                              ? 'bg-emerald-100 dark:bg-emerald-950/40 text-emerald-600 dark:text-emerald-400'
                              : 'bg-rose-100 dark:bg-rose-950/40 text-rose-600 dark:text-rose-400'
                          }`}
                        >
                          {isValid ? <CheckCircle2 className="w-3 h-3" /> : <AlertTriangle className="w-3 h-3" />}
                          {isValid ? '有效' : '已失效'}
                        </span>
                        <p className="text-[10px] text-slate-400 mt-0.5">
                          {acc.active_targets_count} 个火花目标
                        </p>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Recent Stream */}
        <div className="rounded-2xl bg-white dark:bg-slate-900 p-5 border border-slate-200/80 dark:border-slate-800/80 shadow-sm flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">最新互动流水</h2>
              <button
                onClick={() => onNavigate('logs')}
                className="text-xs font-medium text-orange-600 dark:text-orange-400 hover:underline"
              >
                查看全部
              </button>
            </div>

            {recentLogs.length === 0 ? (
              <p className="text-xs text-slate-400 text-center py-8">暂无执行流水记录</p>
            ) : (
              <div className="space-y-3">
                {recentLogs.map((log) => {
                  const isSuccess = log.status === 'SUCCESS';
                  return (
                    <div key={log.id} className="text-xs border-b border-slate-100 dark:border-slate-800/60 pb-2.5 last:border-0">
                      <div className="flex items-center justify-between">
                        <span className="font-medium text-slate-800 dark:text-slate-200">
                          {log.account_alias}
                        </span>
                        <span
                          className={`text-[10px] px-1.5 py-0.5 rounded font-medium ${
                            isSuccess
                              ? 'bg-emerald-100 dark:bg-emerald-900/30 text-emerald-600 dark:text-emerald-400'
                              : 'bg-rose-100 dark:bg-rose-900/30 text-rose-600 dark:text-rose-400'
                          }`}
                        >
                          {isSuccess ? '成功' : '失败'}
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-1 truncate">
                        {log.message}
                      </p>
                      <span className="text-[10px] text-slate-400 font-mono mt-0.5 block">
                        {log.created_at ? new Date(log.created_at).toLocaleTimeString() : ''}
                      </span>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
