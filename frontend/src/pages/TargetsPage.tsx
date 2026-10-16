import React, { useEffect, useRef, useState } from 'react';
import {
  Sparkles,
  Plus,
  Play,
  Trash2,
  Edit3,
  CheckCircle2,
  AlertTriangle,
  Loader2,
  X,
  Flame,
  RefreshCw,
  Clock,
} from 'lucide-react';
import { api } from '../api/client';
import { AccountDto, DouyinFriend, SparkTarget } from '../types';
import { useToast } from '../components/ui/Toast';
import { ConfirmModal } from '../components/ui/ConfirmModal';
import { CustomSelect } from '../components/ui/CustomSelect';
import { ModalPortal } from '../components/ui/ModalPortal';
import { parseSparkStatus } from '../utils/spark';
import { accountDisplayName, formatDisplayName } from '../utils/displayName';
import { getTodaySparkStatus } from '../utils/todayStatus';
import { refreshSummaryMessage, refreshTargetsSequentially } from '../utils/refreshTargets';

interface Props {
  active?: boolean;
  refreshTrigger: number;
  onRefresh: () => void;
}

export const TargetsPage: React.FC<Props> = ({ active = true, refreshTrigger, onRefresh }) => {
  const toast = useToast();
  const [targets, setTargets] = useState<SparkTarget[]>([]);
  const [accounts, setAccounts] = useState<AccountDto[]>([]);
  const [selectedAccountId, setSelectedAccountId] = useState<string>('');
  const [isLoading, setIsLoading] = useState(true);
  const [isPageRefreshing, setIsPageRefreshing] = useState(false);
  const requestId = useRef(0);
  const syncBusy = useRef(false);
  const [page, setPage] = useState(0);
  const pageSize = 20;
  const [now, setNow] = useState(() => new Date());

  // Modals
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [editTarget, setEditTarget] = useState<SparkTarget | null>(null);
  const [deleteTargetItem, setDeleteTargetItem] = useState<SparkTarget | null>(null);

  // Add Target Form States
  const [targetAccountId, setTargetAccountId] = useState('');
  const [accountFriends, setAccountFriends] = useState<DouyinFriend[]>([]);
  const [isFetchingFriends, setIsFetchingFriends] = useState(false);
  const [isManualInput, setIsManualInput] = useState(false);

  const [selectedFriendSecUid, setSelectedFriendSecUid] = useState('');
  const [targetNickname, setTargetNickname] = useState('');
  const [remarkName, setRemarkName] = useState('');
  const [targetSecUid, setTargetSecUid] = useState('');
  const [targetUid, setTargetUid] = useState('');
  const [sparkDays, setSparkDays] = useState(0);
  const [sparkDesc] = useState('');
  const [isSparkedToday, setIsSparkedToday] = useState(false);
  const [conversationType, setConversationType] = useState(1);
  const [conversationId, setConversationId] = useState('');
  const [messageTemplate, setMessageTemplate] = useState('🔥');
  const [formError, setFormError] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Testing & Syncing Target Loading State
  const [testingIds, setTestingIds] = useState<Set<string>>(new Set());
  const testingInFlight = useRef(new Set<string>());
  const [syncingIds, setSyncingIds] = useState<Set<string>>(new Set());

  const loadData = async () => {
    const currentRequest = ++requestId.current;
    try {
      const [accs, tgts] = await Promise.all([
        api.getAccounts(), api.getTargets(selectedAccountId || undefined),
      ]);
      if (currentRequest !== requestId.current) return;
      setAccounts(accs);
      setTargets(tgts);
      setNow(new Date());
    } catch (e) {
      if (currentRequest === requestId.current) toast.error(`状态加载失败：${e instanceof Error ? e.message : '请重试'}`);
    } finally {
      if (currentRequest === requestId.current) setIsLoading(false);
    }
  };

  useEffect(() => {
    if (active) loadData();
    return () => { requestId.current += 1; };
  }, [active, selectedAccountId, refreshTrigger]);

  useEffect(() => {
    if (!active) return;
    const timer = window.setInterval(() => setNow(new Date()), 1000);
    const refreshClock = () => setNow(new Date());
    document.addEventListener('visibilitychange', refreshClock);
    return () => { window.clearInterval(timer); document.removeEventListener('visibilitychange', refreshClock); };
  }, [active]);

  useEffect(() => {
    if (active) return;
    setIsAddModalOpen(false);
    setEditTarget(null);
    setDeleteTargetItem(null);
  }, [active]);

  const invalidateToday = (accountId: string) => {
    requestId.current += 1;
    setTargets((items) => items.map((item) => item.account_id === accountId
      ? { ...item, is_sparked_today: null, today_checked_at: null } : item));
  };

  const handleRefreshAll = async () => {
    if (syncBusy.current) return;
    syncBusy.current = true;
    setIsPageRefreshing(true);
    try {
      const scope = selectedAccountId ? targets.filter((target) => target.account_id === selectedAccountId) : targets;
      if (!scope.length) { toast.info('当前范围没有可刷新的目标'); return; }
      const result = await refreshTargetsSequentially(scope, refreshTargetRow);
      if (result.failures.length) {
        if (result.confirmed) toast.info(refreshSummaryMessage(result));
        else toast.error(refreshSummaryMessage(result));
      } else toast.success(refreshSummaryMessage(result));
    } finally {
      syncBusy.current = false;
      setIsPageRefreshing(false);
    }
  };

  // 弹窗同步与主刷新共享互斥及今日状态失效流程。
  useEffect(() => {
    if (!targetAccountId || !isAddModalOpen || syncBusy.current) return;
    let cancelled = false;
    syncBusy.current = true;
    setIsFetchingFriends(true);
    setIsPageRefreshing(true);
    setAccountFriends([]);
    invalidateToday(targetAccountId);
    void (async () => {
      try {
        const result = await api.syncFriendsWithStatus(targetAccountId);
        if (!cancelled) {
          setAccountFriends(result.data);
          if (result.today_status?.unconfirmed) toast.info(result.message);
        }
      } catch (e) {
        if (!cancelled) {
          setAccountFriends([]);
          setFormError(`同步失败：${e instanceof Error ? e.message : '请稍后重试'}`);
        }
      } finally {
        // 即使弹窗已关闭，也要重读服务端已失效的主列表状态。
        await loadData();
        syncBusy.current = false;
        setIsFetchingFriends(false);
        setIsPageRefreshing(false);
      }
    })();
    return () => { cancelled = true; };
  }, [targetAccountId, isAddModalOpen]);

  const handleSelectFriendFromDropdown = (sec_uid: string) => {
    setSelectedFriendSecUid(sec_uid);
    if (!sec_uid) return;
    const found = accountFriends.find((f) => f.sec_uid === sec_uid);
    if (found) {
      setTargetSecUid(found.sec_uid);
      setTargetUid(found.uid || '');
      setTargetNickname(found.nickname || '');
      setRemarkName(found.remark_name || '');
      setSparkDays(found.spark_days ?? 0);
      setIsSparkedToday(Boolean(found.is_sparked_today));
      setConversationId(found.conversation_id || '');
      setConversationType(found.target_type || 1);
    }
  };

  const handleCreateTarget = async (e: React.FormEvent) => {
    e.preventDefault();
    const finalSecUid = targetSecUid.trim() || selectedFriendSecUid.trim();
    if (!targetAccountId || !finalSecUid) {
      setFormError('所属账号与好友选择/SecUID 均为必填项');
      return;
    }
    setIsSubmitting(true);
    setFormError('');
    try {
      await api.createTarget({
        account_id: targetAccountId,
        target_nickname: targetNickname.trim(),
        remark_name: remarkName.trim() || undefined,
        target_sec_uid: finalSecUid,
        target_uid: targetUid.trim() || undefined,
        conversation_id: conversationId.trim() || undefined,
        conversation_type: conversationType,
        spark_days: sparkDays,
        spark_desc: sparkDesc || undefined,
        is_sparked_today: isSparkedToday || undefined,
        message_template: messageTemplate.trim() || '🔥',
      });
      toast.success('续火花目标添加成功');
      setIsAddModalOpen(false);
      setTargetNickname('');
      setRemarkName('');
      setTargetSecUid('');
      setSelectedFriendSecUid('');
      setSparkDays(0);
      loadData();
      onRefresh();
    } catch (e: any) {
      setFormError(e.message || '添加目标失败');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleToggleEnabled = async (target: SparkTarget) => {
    try {
      await api.updateTarget(target.id, { is_enabled: !target.is_enabled });
      toast.success(target.is_enabled ? '已暂停该目标续火花监控' : '已开启该目标续火花监控');
      loadData();
      onRefresh();
    } catch (e: any) {
      toast.error(`更新状态失败: ${e.message}`);
    }
  };

  const handleEditTarget = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editTarget) return;
    setIsSubmitting(true);
    try {
      await api.updateTarget(editTarget.id, {
        message_template: messageTemplate.trim() || '🔥',
        remark_name: remarkName.trim() || undefined,
      });
      toast.success('修改目标配置成功');
      setEditTarget(null);
      loadData();
      onRefresh();
    } catch (e: any) {
      toast.error(`修改失败: ${e.message}`);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleDeleteTargetConfirm = async () => {
    if (!deleteTargetItem) return;
    const { id, target_nickname } = deleteTargetItem;
    setDeleteTargetItem(null);
    try {
      await api.deleteTarget(id);
      toast.success(`目标「${target_nickname}」已成功移除`);
      loadData();
      onRefresh();
    } catch (e: any) {
      toast.error(`删除失败: ${e.message}`);
    }
  };

  const handleTestSpark = async (id: string) => {
    if (testingInFlight.current.has(id)) return;
    testingInFlight.current.add(id);
    setTestingIds((prev) => new Set(prev).add(id));
    try {
      const res = await api.testTarget(id);
      if (res.data?.success) {
        toast.success(res.message);
      } else {
        toast.error(res.message);
      }
      loadData();
      onRefresh();
    } catch (e: any) {
      toast.error(`发送失败: ${e.message}`);
    } finally {
      testingInFlight.current.delete(id);
      setTestingIds((prev) => {
        const next = new Set(prev);
        next.delete(id);
        return next;
      });
    }
  };

  const refreshTargetRow = async (target: SparkTarget) => {
    requestId.current += 1;
    setTargets((items) => items.map((item) => item.id === target.id
      ? { ...item, is_sparked_today: null, today_checked_at: null } : item));
    setSyncingIds((prev) => new Set(prev).add(target.id));
    try {
      const result = await api.refreshTarget(target.id);
      setTargets((items) => items.map((item) => item.id === target.id ? result.data : item));
      if (result.im_history_status) setAccounts((items) => items.map((account) => account.id === target.account_id
        ? { ...account, im_history_status: result.im_history_status, im_history_expires_at: result.im_history_expires_at ?? null } : account));
      setNow(new Date());
      return result;
    } catch (e: unknown) {
      try {
        const latest = await api.getTarget(target.id);
        setTargets((items) => items.map((item) => item.id === target.id ? latest : item));
      } catch { /* 只保留本行未知状态，禁止用旧缓存恢复。 */ }
      throw e;
    } finally {
      setSyncingIds((prev) => {
        const next = new Set(prev);
        next.delete(target.id);
        return next;
      });
    }
  };

  const handleSyncSingleTarget = async (target: SparkTarget) => {
    if (syncBusy.current) return;
    syncBusy.current = true;
    try {
      const result = await refreshTargetRow(target);
      if (result.confirmed) toast.success(result.message);
      else toast.info(result.message);
    } catch (error) { toast.error(`刷新失败：${error instanceof Error ? error.message : '请求失败'}`); }
    finally { syncBusy.current = false; }
  };

  useEffect(() => { setPage(0); }, [selectedAccountId]);
  const totalPages = Math.max(1, Math.ceil(targets.length / pageSize));
  const currentPage = Math.min(page, totalPages - 1);

  // 今日状态只来自当天有效的系统发送或完整消息历史证据。

  const accountFilterOptions = [
    { value: '', label: '全部账号' },
    ...accounts.map((a) => ({
      value: a.id,
      label: accountDisplayName(a.nickname, a.alias),
    })),
  ];

  const modalAccountOptions = accounts.map((a) => ({
    value: a.id,
    label: accountDisplayName(a.nickname, a.alias),
  }));

  const friendDropdownOptions = [
    { value: '', label: '-- 请选择要续火花的好友或群聊 --' },
    ...accountFriends.map((f) => {
      const sparkInfo = parseSparkStatus(f.spark_days, f.spark_desc);
      const isGroup = f.target_type === 2;
      const displayName = `${isGroup ? '👥 [群聊] ' : ''}${formatDisplayName(f.nickname, f.remark_name)}`;
      return {
        value: f.sec_uid,
        label: displayName,
        subLabel: `${sparkInfo.isLit ? `🔥 ${sparkInfo.label} · ` : '🔥 未点亮 · '}${isGroup ? `群ID: ${f.conversation_id || f.sec_uid}` : `UID: ${f.uid || '未获取'}`}`,
      };
    }),
  ];
  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
            续火花对象
          </h1>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            配置每个账号专属的续火花好友、打招呼文案与火花状态
          </p>
        </div>

        <div className="flex items-center gap-2">
          {/* Custom Select Filter */}
          <div className="w-44">
            <CustomSelect
              options={accountFilterOptions}
              value={selectedAccountId}
              onChange={(val) => setSelectedAccountId(val)}
              disabled={isPageRefreshing}
              placeholder="按账号筛选"
            />
          </div>

          <button
            onClick={handleRefreshAll}
            disabled={isPageRefreshing}
            title="刷新当前范围全部目标的火花与今日状态"
            className="p-2 rounded-xl border border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isPageRefreshing ? 'animate-spin' : ''}`} />
          </button>

          <button
            disabled={isPageRefreshing}
            onClick={() => {
              const defaultAcc = accounts[0]?.id || '';
              setTargetAccountId(defaultAcc);
              setSelectedFriendSecUid('');
              setTargetNickname('');
              setTargetSecUid('');
              setTargetUid('');
              setSparkDays(0);
              setMessageTemplate('🔥');
              setIsManualInput(false);
              setFormError('');
              setIsAddModalOpen(true);
            }}
            className="flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium rounded-xl bg-orange-500 hover:bg-orange-600 active:scale-95 text-white transition shadow-sm shadow-orange-500/20"
          >
            <Plus className="w-4 h-4" />
            <span>添加目标</span>
          </button>
        </div>
      </div>

      {/* Target Table / List */}
      {isLoading ? (
        <div className="flex justify-center py-16">
          <Loader2 className="w-8 h-8 text-orange-500 animate-spin" />
        </div>
      ) : targets.length === 0 ? (
        <div className="text-center py-16 rounded-2xl bg-white dark:bg-slate-900 border border-dashed border-slate-200 dark:border-slate-800 p-8">
          <Sparkles className="w-12 h-12 text-slate-400 mx-auto mb-3" />
          <h3 className="text-sm font-semibold text-slate-800 dark:text-slate-200">暂无续火花目标</h3>
          <p className="text-xs text-slate-500 dark:text-slate-400 max-w-sm mx-auto mt-1">
            点击上方“添加目标”即可从好友下拉列表中选择好友，也可以在“账号管理”中一键批量导入。
          </p>
        </div>
      ) : (
        <div className="overflow-x-auto rounded-2xl bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800/80 shadow-sm">
          <table className="min-w-[960px] w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-200/80 dark:border-slate-800/80 bg-slate-50/75 dark:bg-slate-800/50 text-slate-500 dark:text-slate-400 font-medium">
                <th className="py-3 px-4 whitespace-nowrap min-w-[180px]">好友 / 续火花对象</th>
                <th className="py-3 px-4 whitespace-nowrap min-w-[110px]">所属账号</th>
                <th className="py-3 px-4 whitespace-nowrap min-w-[110px]">火花状态</th>
                <th className="py-3 px-4 whitespace-nowrap min-w-[150px]">今天续火状态</th>
                <th className="py-3 px-4 whitespace-nowrap min-w-[80px]">消息模板</th>
                <th className="py-3 px-4 whitespace-nowrap min-w-[70px]">监控</th>
                <th className="py-3 px-4 whitespace-nowrap min-w-[130px]">最近互动</th>
                <th className="py-3 px-4 whitespace-nowrap min-w-[150px] text-right sticky right-0 bg-slate-50/95 dark:bg-slate-800/95 shadow-[-4px_0_6px_-2px_rgba(0,0,0,0.05)]">操作</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60">
              {targets.slice(currentPage * pageSize, (currentPage + 1) * pageSize).map((tgt) => {
                const acc = accounts.find((a) => a.id === tgt.account_id);
                const isTesting = testingIds.has(tgt.id);
                const isSyncing = syncingIds.has(tgt.id);
                const todayStatus = getTodaySparkStatus(tgt, now);

                return (
                  <tr
                    key={tgt.id}
                    className="hover:bg-slate-50/50 dark:hover:bg-slate-800/30 transition group"
                  >
                    <td className="py-3 px-4">
                      <div className="flex items-center gap-3 min-w-0">
                        {tgt.target_avatar ? (
                          <img
                            src={tgt.target_avatar}
                            alt=""
                            referrerPolicy="no-referrer"
                            className="w-9 h-9 rounded-full object-cover border border-slate-200 dark:border-slate-700 shrink-0"
                            onError={(e) => {
                              // 头像失效或防盗链时平滑替换为名字缩写
                              e.currentTarget.style.display = 'none';
                              const fallback = e.currentTarget.nextElementSibling as HTMLElement;
                              if (fallback) fallback.style.display = 'flex';
                            }}
                          />
                        ) : null}
                        <div
                          className="w-9 h-9 rounded-full bg-amber-100 dark:bg-amber-950/40 text-amber-600 dark:text-amber-400 font-bold flex items-center justify-center shrink-0"
                          style={{ display: tgt.target_avatar ? 'none' : 'flex' }}
                        >
                          {(tgt.remark_name || tgt.target_nickname).slice(0, 1)}
                        </div>
                        <div className="min-w-0 flex-1">
                          <div className="flex items-center gap-1.5 flex-wrap">
                            <p className="font-semibold text-slate-800 dark:text-slate-200 truncate max-w-[150px] sm:max-w-[200px]" title={tgt.remark_name ? `${tgt.remark_name} (${tgt.target_nickname})` : tgt.target_nickname}>
                              {tgt.remark_name ? (
                                <span>
                                  {tgt.remark_name}
                                  <span className="ml-1 text-[11px] font-normal text-slate-400">({tgt.target_nickname})</span>
                                </span>
                              ) : (
                                tgt.target_nickname
                              )}
                            </p>
                            {tgt.conversation_type === 2 && (
                              <span className="px-1.5 py-0.5 rounded text-[10px] bg-blue-100 dark:bg-blue-950/60 text-blue-700 dark:text-blue-300 font-medium shrink-0">
                                👥 群聊
                              </span>
                            )}
                          </div>
                          <p className="font-mono text-[10px] text-slate-400 truncate max-w-[140px]" title={tgt.conversation_type === 2 ? `群ID: ${tgt.conversation_id || tgt.target_sec_uid}` : tgt.target_sec_uid}>
                            {tgt.conversation_type === 2 ? `群ID: ${tgt.conversation_id || tgt.target_sec_uid}` : `${tgt.target_sec_uid.slice(0, 18)}...`}
                          </p>
                        </div>
                      </div>
                    </td>

                    <td className="py-3 px-4 whitespace-nowrap">
                      <span className="px-2 py-0.5 rounded-lg bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 font-medium">
                        {acc ? accountDisplayName(acc.nickname, acc.alias) : '未知账号'}
                      </span>
                    </td>
                    {/* 火花状态 */}
                    <td className="py-3 px-4">
                      {(() => {
                        const sparkInfo = parseSparkStatus(tgt.spark_days, tgt.spark_desc);
                        return (
                          <span className={`inline-flex items-center gap-1 whitespace-nowrap shrink-0 font-semibold px-2.5 py-1 rounded-lg border text-xs ${sparkInfo.badgeClass}`}>
                            <Flame className={`w-3.5 h-3.5 shrink-0 ${sparkInfo.isLit ? 'fill-current text-orange-500' : 'text-slate-400'}`} />
                            <span>{sparkInfo.label}</span>
                          </span>
                        );
                      })()}
                    </td>

                    {/* 今日状态只由本目标的已确认记录决定。 */}
                    <td className="py-3 px-4 whitespace-nowrap">
                      <span title={todayStatus.label} className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[11px] font-semibold border ${todayStatus.color}`}>
                        {todayStatus.code === 'SUCCESS' && <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />}
                        {todayStatus.code === 'PENDING' && <Clock className="w-3.5 h-3.5 shrink-0" />}
                        {todayStatus.code === 'FAILED' && <AlertTriangle className="w-3.5 h-3.5 shrink-0" />}
                        {todayStatus.code === 'UNKNOWN' && <Clock className="w-3.5 h-3.5 shrink-0" />}
                        <span className="whitespace-nowrap">{todayStatus.label}</span>
                      </span>
                    </td>

                    <td className="py-3 px-4">
                      <span className="font-mono text-slate-600 dark:text-slate-300 px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-800">
                        {tgt.message_template}
                      </span>
                    </td>

                    <td className="py-3 px-4">
                      <button
                        onClick={() => handleToggleEnabled(tgt)}
                        className={`relative inline-flex h-5 w-9 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
                          tgt.is_enabled ? 'bg-orange-500' : 'bg-slate-300 dark:bg-slate-700'
                        }`}
                      >
                        <span
                          className={`pointer-events-none inline-block h-4 w-4 transform rounded-full bg-white shadow-lg ring-0 transition duration-200 ease-in-out ${
                            tgt.is_enabled ? 'translate-x-4' : 'translate-x-0'
                          }`}
                        />
                      </button>
                    </td>

                    <td className="py-3 px-4 min-w-0">
                      {tgt.last_sent_at ? (
                        <div className="min-w-0">
                          <p className="text-[11px] text-slate-600 dark:text-slate-300 font-mono whitespace-nowrap">
                            {new Date(tgt.last_sent_at).toLocaleDateString()}{' '}
                            {new Date(tgt.last_sent_at).toLocaleTimeString([], {
                              hour: '2-digit',
                              minute: '2-digit',
                            })}
                          </p>
                          {tgt.last_error && (
                            <p className="text-[10px] text-rose-500 truncate max-w-[140px]" title={tgt.last_error}>
                              {tgt.last_error}
                            </p>
                          )}
                        </div>
                      ) : (
                        <span className="text-slate-400 whitespace-nowrap">暂无系统发送记录</span>
                      )}
                    </td>

                    {/* Operations with Sticky Column on Right */}
                    <td className="py-3 px-4 text-right sticky right-0 bg-white dark:bg-slate-900 group-hover:bg-slate-50/95 dark:group-hover:bg-slate-800/95 shadow-[-4px_0_6px_-2px_rgba(0,0,0,0.05)] transition-colors">
                      <div className="flex items-center justify-end gap-1 shrink-0 whitespace-nowrap">
                        <button
                          onClick={() => handleSyncSingleTarget(tgt)}
                          disabled={isPageRefreshing || isSyncing}
                          className="p-1.5 text-slate-500 hover:text-orange-500 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 transition"
                          title="从抖音重新同步该好友的昵称与火花天数"
                        >
                          <RefreshCw className={`w-3.5 h-3.5 ${isSyncing ? 'animate-spin text-orange-500' : ''}`} />
                        </button>

                        <button
                          onClick={() => handleTestSpark(tgt.id)}
                          disabled={isTesting}
                          className="flex items-center gap-1 px-2.5 py-1 text-[11px] font-medium rounded-lg bg-orange-50 dark:bg-orange-950/30 text-orange-600 dark:text-orange-400 hover:bg-orange-100 transition disabled:opacity-40 whitespace-nowrap shrink-0"
                          title="立即续火花"
                        >
                          {isTesting ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5 fill-current" />}
                          <span className="whitespace-nowrap">{isTesting ? '处理中' : '续火花'}</span>
                        </button>

                        <button
                          onClick={() => {
                            setEditTarget(tgt);
                            setTargetNickname(tgt.target_nickname);
                            setRemarkName(tgt.remark_name || '');
                            setMessageTemplate(tgt.message_template);
                          }}
                          className="p-1.5 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800"
                          title="修改配置"
                        >
                          <Edit3 className="w-3.5 h-3.5" />
                        </button>

                        <button
                          onClick={() => setDeleteTargetItem(tgt)}
                          className="p-1.5 text-slate-400 hover:text-rose-500 rounded-lg hover:bg-rose-50 dark:hover:bg-rose-950/30"
                          title="删除目标"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      {targets.length > 0 && (
        <div className="flex items-center justify-between text-xs text-slate-500 dark:text-slate-400">
          <span>共 {targets.length} 个目标</span>
          <div className="flex items-center gap-3">
            <button type="button" aria-label="上一页目标" disabled={currentPage === 0} onClick={() => setPage(currentPage - 1)} className="px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 disabled:opacity-40">上一页</button>
            <span>{currentPage + 1} / {totalPages}</span>
            <button type="button" aria-label="下一页目标" disabled={currentPage + 1 >= totalPages} onClick={() => setPage(currentPage + 1)} className="px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 disabled:opacity-40">下一页</button>
          </div>
        </div>
      )}

      {/* Add Target Modal */}
      {isAddModalOpen && (
        <ModalPortal>
          <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/60 backdrop-blur-sm p-4 overflow-y-auto">
          <div className="relative w-full max-w-md rounded-2xl bg-white dark:bg-slate-900 p-6 shadow-2xl border border-slate-200 dark:border-slate-800 animate-in fade-in zoom-in-95 duration-150">
            <button
              onClick={() => setIsAddModalOpen(false)}
              className="absolute right-4 top-4 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200"
            >
              <X className="w-5 h-5" />
            </button>

            <h3 className="text-base font-bold text-slate-900 dark:text-slate-100 mb-1">
              添加续火花目标
            </h3>
            <p className="text-xs text-slate-500 dark:text-slate-400 mb-4">
              可直接从好友下拉列表中选择，或手动指定好友 SecUID
            </p>

            <form onSubmit={handleCreateTarget} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                  所属账号 *
                </label>
                <CustomSelect
                  options={modalAccountOptions}
                  value={targetAccountId}
                  onChange={(val) => setTargetAccountId(val)}
                  disabled={isFetchingFriends}
                  placeholder="请选择所属账号"
                />
              </div>

              {!isManualInput ? (
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <label className="text-xs font-medium text-slate-700 dark:text-slate-300 flex items-center gap-1.5">
                      <span>选择好友 (下拉列表) *</span>
                      {isFetchingFriends && <Loader2 className="w-3 h-3 text-orange-500 animate-spin" />}
                    </label>
                    <button
                      type="button"
                      onClick={() => setIsManualInput(true)}
                      className="text-[11px] text-orange-600 dark:text-orange-400 hover:underline"
                    >
                      切换为手动输入
                    </button>
                  </div>

                  <CustomSelect
                    options={friendDropdownOptions}
                    value={selectedFriendSecUid}
                    onChange={(val) => handleSelectFriendFromDropdown(val)}
                    placeholder="-- 请选择要续火花的好友 --"
                  />
                  {accountFriends.length === 0 && !isFetchingFriends && (
                    <p className="text-[11px] text-amber-500 mt-1">
                      当前账号暂未同步好友列表，可直接切换为手动输入或在账号页点击“同步好友”。
                    </p>
                  )}
                </div>
              ) : (
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <label className="text-xs font-medium text-slate-700 dark:text-slate-300">
                      好友 SecUID (sec_user_id) *
                    </label>
                    {accountFriends.length > 0 && (
                      <button
                        type="button"
                        onClick={() => setIsManualInput(false)}
                        className="text-[11px] text-orange-600 dark:text-orange-400 hover:underline"
                      >
                        切换为下拉选择
                      </button>
                    )}
                  </div>
                  <input
                    type="text"
                    required
                    value={targetSecUid}
                    onChange={(e) => setTargetSecUid(e.target.value)}
                    placeholder="抖音个人主页链接中的 sec_uid 参数"
                    className="w-full px-3 py-2 text-xs font-mono rounded-xl border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 focus:ring-2 focus:ring-orange-500 focus:outline-none"
                  />
                </div>
              )}

              <div>
                <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                  好友
                </label>
                <div className="flex items-center min-h-[34px] px-3 py-2 text-xs font-semibold rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/70 text-slate-800 dark:text-slate-100">
                  {targetNickname || remarkName ? formatDisplayName(targetNickname, remarkName) : '未选择'}
                </div>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                    火花状态
                  </label>
                  {(() => {
                    const sparkInfo = parseSparkStatus(sparkDays, sparkDesc);
                    return (
                      <div className={`flex items-center gap-2 px-3 py-2 text-xs font-semibold rounded-xl border ${sparkInfo.badgeClass}`}>
                        <Flame className={`w-4 h-4 ${sparkInfo.isLit ? 'fill-current text-orange-500' : 'text-slate-400'}`} />
                        <span>{sparkInfo.label}</span>
                      </div>
                    );
                  })()}
                </div>

                <div>
                  <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                    发送文案模板
                  </label>
                  <input
                    type="text"
                    value={messageTemplate}
                    onChange={(e) => setMessageTemplate(e.target.value)}
                    placeholder="默认 🔥"
                    className="w-full px-3 py-2 text-xs rounded-xl border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 focus:ring-2 focus:ring-orange-500 focus:outline-none"
                  />
                </div>
              </div>

              {formError && <p className="text-xs text-rose-500">{formError}</p>}

              <div className="flex gap-2.5 pt-2">
                <button
                  type="button"
                  onClick={() => setIsAddModalOpen(false)}
                  className="flex-1 px-4 py-2 text-xs font-medium rounded-xl border border-slate-200 dark:border-slate-800 hover:bg-slate-100 dark:hover:bg-slate-800"
                >
                  取消
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting || isFetchingFriends}
                  className="flex-1 flex items-center justify-center gap-1.5 px-4 py-2 text-xs font-medium rounded-xl bg-orange-500 hover:bg-orange-600 text-white disabled:opacity-50"
                >
                  {isSubmitting ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Plus className="w-3.5 h-3.5" />}
                  <span>确认添加</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      </ModalPortal>
      )}

      {/* Edit Target Modal */}
      {editTarget && (
        <ModalPortal>
          <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/60 backdrop-blur-sm p-4 overflow-y-auto">
          <div className="relative w-full max-w-md rounded-2xl bg-white dark:bg-slate-900 p-6 shadow-2xl border border-slate-200 dark:border-slate-800 animate-in fade-in zoom-in-95 duration-150">
            <button
              onClick={() => setEditTarget(null)}
              className="absolute right-4 top-4 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200"
            >
              <X className="w-5 h-5" />
            </button>

            <h3 className="text-base font-bold text-slate-900 dark:text-slate-100 mb-1">
              修改目标配置: {editTarget.target_nickname}
            </h3>
            <p className="text-xs text-slate-500 dark:text-slate-400 mb-4">
              {formatDisplayName(editTarget.target_nickname, editTarget.remark_name)}
            </p>

            <form onSubmit={handleEditTarget} className="space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                    抖音原生昵称
                  </label>
                  <div className="flex items-center min-h-[34px] px-3 py-2 text-xs font-semibold rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/70 text-slate-800 dark:text-slate-100 truncate">
                    {editTarget.target_nickname}
                  </div>
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                    好友备注名 (优先在列表中展示)
                  </label>
                  <input
                    type="text"
                    value={remarkName}
                    onChange={(e) => setRemarkName(e.target.value)}
                    placeholder="为空则使用抖音原生昵称"
                    className="w-full px-3 py-2 text-xs rounded-xl border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 focus:ring-2 focus:ring-orange-500 focus:outline-none"
                  />
                </div>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                    火花状态
                  </label>
                  {(() => {
                    const sparkInfo = parseSparkStatus(editTarget.spark_days, editTarget.spark_desc);
                    return (
                      <div className={`flex items-center gap-2 px-3 py-2 text-xs font-semibold rounded-xl border ${sparkInfo.badgeClass}`}>
                        <Flame className={`w-4 h-4 ${sparkInfo.isLit ? 'fill-current text-orange-500' : 'text-slate-400'}`} />
                        <span>{sparkInfo.label}</span>
                      </div>
                    );
                  })()}
                </div>

                <div>
                  <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                    发送文案模板
                  </label>
                  <input
                    type="text"
                    value={messageTemplate}
                    onChange={(e) => setMessageTemplate(e.target.value)}
                    placeholder="默认 🔥"
                    className="w-full px-3 py-2 text-xs rounded-xl border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 focus:ring-2 focus:ring-orange-500 focus:outline-none"
                  />
                </div>
              </div>

              <div className="flex gap-2.5 pt-2">
                <button
                  type="button"
                  onClick={() => setEditTarget(null)}
                  className="flex-1 px-4 py-2 text-xs font-medium rounded-xl border border-slate-200 dark:border-slate-800 hover:bg-slate-100 dark:hover:bg-slate-800"
                >
                  取消
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="flex-1 flex items-center justify-center gap-1.5 px-4 py-2 text-xs font-medium rounded-xl bg-orange-500 hover:bg-orange-600 text-white disabled:opacity-50"
                >
                  {isSubmitting ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Edit3 className="w-3.5 h-3.5" />}
                  <span>保存修改</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      </ModalPortal>
      )}

      {/* Delete Target Confirm Modal */}
      <ConfirmModal
        isOpen={Boolean(deleteTargetItem)}
        title="确认删除续火花目标"
        description={`确定从监控列表中删除目标「${deleteTargetItem?.target_nickname}」吗？`}
        confirmText="确认删除"
        isDanger={true}
        onConfirm={handleDeleteTargetConfirm}
        onCancel={() => setDeleteTargetItem(null)}
      />
    </div>
  );
};
