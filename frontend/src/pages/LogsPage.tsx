import React, { useEffect, useRef, useState } from 'react';
import {
  ScrollText,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Loader2,
  ChevronLeft,
  ChevronRight,
  ShieldAlert,
  Flame,
} from 'lucide-react';
import { api } from '../api/client';
import { AccountDto, SparkLog } from '../types';
import { CustomSelect } from '../components/ui/CustomSelect';
import { useToast } from '../components/ui/Toast';

interface Props {
  refreshTrigger: number;
  active?: boolean;
}

export const LogsPage: React.FC<Props> = ({ active = true, refreshTrigger }) => {
  const toast = useToast();
  const [logs, setLogs] = useState<SparkLog[]>([]);
  const [total, setTotal] = useState(0);
  const [accounts, setAccounts] = useState<AccountDto[]>([]);
  const [selectedAccount, setSelectedAccount] = useState('');
  const [selectedStatus, setSelectedStatus] = useState('');
  const [page, setPage] = useState(0);
  const pageSize = 20;
  const [isLoading, setIsLoading] = useState(true);
  const [hasLoaded, setHasLoaded] = useState(false);
  const requestId = useRef(0);

  const loadLogs = async () => {
    const currentRequest = ++requestId.current;
    setIsLoading(true);
    try {
      const [accs, logsData] = await Promise.all([
        api.getAccounts().catch(() => []),
        api.getLogs({
          limit: pageSize,
          offset: page * pageSize,
          account_id: selectedAccount || undefined,
          status: selectedStatus || undefined,
        }),
      ]);
      if (currentRequest !== requestId.current) return;
      setAccounts(accs);
      setLogs(logsData.items);
      setTotal(logsData.total);
    } catch (e) {
      if (currentRequest === requestId.current) {
        toast.error(`日志加载失败：${e instanceof Error ? e.message : '请重试'}`);
      }
    } finally {
      if (currentRequest === requestId.current) {
        setIsLoading(false);
        setHasLoaded(true);
      }
    }
  };

  useEffect(() => {
    if (active) loadLogs();
    return () => { requestId.current += 1; };
  }, [active, page, selectedAccount, selectedStatus, refreshTrigger]);

  const totalPages = Math.ceil(total / pageSize) || 1;

  const accountOptions = [
    { value: '', label: '全部账号' },
    ...accounts.map((a) => ({
      value: a.id,
      label: a.alias,
      subLabel: a.nickname ? `昵称: ${a.nickname}` : undefined,
    })),
  ];

  const statusOptions = [
    { value: '', label: '全部状态' },
    { value: 'SUCCESS', label: '仅成功' },
    { value: 'FAILED', label: '仅失败' },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
            运行流水日志
          </h1>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            全量记录 Cookie 巡检、安全风控拦截与续火花互动记录
          </p>
        </div>

        {/* Filters with Custom Select */}
        <div className="flex items-center gap-2 flex-wrap">
          <div className="w-40">
            <CustomSelect
              options={accountOptions}
              value={selectedAccount}
              onChange={(val) => {
                setSelectedAccount(val);
                setPage(0);
              }}
              placeholder="按账号筛选"
            />
          </div>

          <div className="w-32">
            <CustomSelect
              options={statusOptions}
              value={selectedStatus}
              onChange={(val) => {
                setSelectedStatus(val);
                setPage(0);
              }}
              placeholder="按状态筛选"
            />
          </div>

          <button
            onClick={loadLogs}
            disabled={isLoading}
            aria-label="刷新日志"
            className="p-2 rounded-xl border border-slate-200 dark:border-slate-800 text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Logs Table */}
      {isLoading && !hasLoaded ? (
        <div className="flex justify-center py-16">
          <Loader2 className="w-8 h-8 text-orange-500 animate-spin" />
        </div>
      ) : logs.length === 0 ? (
        <div className="text-center py-16 rounded-2xl bg-white dark:bg-slate-900 border border-dashed border-slate-200 dark:border-slate-800 p-8">
          <ScrollText className="w-12 h-12 text-slate-400 mx-auto mb-3" />
          <h3 className="text-sm font-semibold text-slate-800 dark:text-slate-200">暂无日志流水</h3>
          <p className="text-xs text-slate-500 dark:text-slate-400 max-w-sm mx-auto mt-1">
            执行检测或发送火花后，记录将实时展示于此处。
          </p>
        </div>
      ) : (
        <div aria-busy={isLoading} className="overflow-x-auto rounded-2xl bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800/80 shadow-sm">
          <table className="w-full min-w-[760px] text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-200/80 dark:border-slate-800/80 bg-slate-50/75 dark:bg-slate-800/50 text-slate-500 dark:text-slate-400 font-medium">
                <th className="py-3 px-4">时间</th>
                <th className="py-3 px-4">执行账号</th>
                <th className="py-3 px-4">目标好友</th>
                <th className="py-3 px-4">操作类型</th>
                <th className="py-3 px-4">执行结果</th>
                <th className="py-3 px-4">详细详情</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60 font-sans">
              {logs.map((log) => {
                const isSuccess = log.status === 'SUCCESS';
                const isCheck = log.action_type !== 'SEND_SPARK' && log.action_type !== 'TEST_SPARK';
                const actionLabel: Record<string, string> = {
                  CHECK_COOKIE: '凭证检测', ACCOUNT_EXECUTION: '账号执行',
                  REFRESH_COOKIE: 'Cookie 更新', SEND_SPARK: '续火花互动',
                  TEST_SPARK: '单次互动', PRE_SEND_CHECK: '发送前检查', POST_SEND_CHECK: '发送后检查',
                };

                return (
                  <tr key={log.id} className="hover:bg-slate-50/50 dark:hover:bg-slate-800/30 transition">
                    <td className="py-3 px-4 text-slate-500 dark:text-slate-400 font-mono text-[11px] whitespace-nowrap">
                      {new Date(log.created_at).toLocaleString()}
                    </td>
                    <td className="py-3 px-4 font-semibold text-slate-800 dark:text-slate-200">
                      {log.account_alias}
                    </td>
                    <td className="py-3 px-4 text-slate-600 dark:text-slate-300">
                      {log.target_nickname || '-'}
                    </td>
                    <td className="py-3 px-4">
                      <span
                        className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold ${
                          isCheck
                            ? 'bg-blue-100 dark:bg-blue-950/40 text-blue-600 dark:text-blue-400'
                            : 'bg-orange-100 dark:bg-orange-950/40 text-orange-600 dark:text-orange-400'
                        }`}
                      >
                        {isCheck ? <ShieldAlert className="w-3 h-3" /> : <Flame className="w-3 h-3" />}
                        {actionLabel[log.action_type] || '执行诊断'}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      <span
                        className={`inline-flex items-center gap-1 font-semibold text-[11px] ${
                          isSuccess
                            ? 'text-emerald-600 dark:text-emerald-400'
                            : 'text-rose-600 dark:text-rose-400'
                        }`}
                      >
                        {isSuccess ? <CheckCircle2 className="w-3.5 h-3.5" /> : <AlertTriangle className="w-3.5 h-3.5" />}
                        {isSuccess ? '成功' : '失败'}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-slate-700 dark:text-slate-300 max-w-xs sm:max-w-sm xl:max-w-md break-words">
                      {log.message}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>

          {/* Pagination bar */}
          <div className="p-3 border-t border-slate-100 dark:border-slate-800/80 flex items-center justify-between text-xs text-slate-500">
            <span>
              共 {total} 条记录，第 {page + 1} / {totalPages} 页
            </span>
            <div className="flex items-center gap-1">
              <button
                onClick={() => setPage((p) => Math.max(0, p - 1))}
                aria-label="上一页日志"
                disabled={isLoading || page === 0}
                className="p-1 rounded-lg border border-slate-200 dark:border-slate-800 disabled:opacity-30 hover:bg-slate-100 dark:hover:bg-slate-800"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
              <button
                onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
                aria-label="下一页日志"
                disabled={isLoading || page >= totalPages - 1}
                className="p-1 rounded-lg border border-slate-200 dark:border-slate-800 disabled:opacity-30 hover:bg-slate-100 dark:hover:bg-slate-800"
              >
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
