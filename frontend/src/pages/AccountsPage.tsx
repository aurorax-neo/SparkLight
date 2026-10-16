import React, { useEffect, useState } from 'react';
import {
  Users,
  Plus,
  RefreshCw,
  CheckCircle2,
  AlertTriangle,
  Play,
  Share2,
  Trash2,
  Edit3,
  Loader2,
  X,
  Bell,
  Sparkles,
  Link2,
  Terminal,
  Copy,
  Check,
} from 'lucide-react';
import { api } from '../api/client';
import { AccountDto, DouyinFriend } from '../types';
import { useToast } from '../components/ui/Toast';
import { ConfirmModal } from '../components/ui/ConfirmModal';
import { CustomCheckbox } from '../components/ui/CustomCheckbox';
import { ModalPortal } from '../components/ui/ModalPortal';
import { copyToClipboard } from '../utils/clipboard';
import { parseSparkStatus } from '../utils/spark';
import { accountDisplayName, formatDisplayName } from '../utils/displayName';
import { TAMPERMONKEY_SCRIPT } from '../utils/tampermonkeyScript';


interface Props {
  active?: boolean;
  refreshTrigger: number;
  onRefresh: () => void;
}

export const AccountsPage: React.FC<Props> = ({ active = true, refreshTrigger, onRefresh }) => {
  const toast = useToast();
  const [accounts, setAccounts] = useState<AccountDto[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  // Modals state
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [editAccount, setEditAccount] = useState<AccountDto | null>(null);
  const [syncModalAccount, setSyncModalAccount] = useState<AccountDto | null>(null);
  const [syncedFriends, setSyncedFriends] = useState<DouyinFriend[]>([]);
  const [selectedFriends, setSelectedFriends] = useState<Set<string>>(new Set());
  const [isSyncing, setIsSyncing] = useState(false);
  const [isBatchAdding, setIsBatchAdding] = useState(false);
  const [syncError, setSyncError] = useState('');

  // Quick sync modal for linking refreshed browser cookies
  const [quickSyncAccount, setQuickSyncAccount] = useState<AccountDto | null>(null);
  const [quickSyncCookie, setQuickSyncCookie] = useState('');
  const [isQuickSyncing, setIsQuickSyncing] = useState(false);

  // Console Injector script modal state
  const [isConsoleModalOpen, setIsConsoleModalOpen] = useState(false);
  const [consoleModalAccount, setConsoleModalAccount] = useState<AccountDto | null>(null);
  const [consoleTargetAccountId, setConsoleTargetAccountId] = useState('');
  const [syncGuideTab, setSyncGuideTab] = useState<'tampermonkey' | 'cli'>('tampermonkey');
  const [isCliCopied, setIsCliCopied] = useState(false);

  // Custom Confirm Dialog States
  const [deleteAccountTarget, setDeleteAccountTarget] = useState<AccountDto | null>(null);
  const [runAccountTarget, setRunAccountTarget] = useState<AccountDto | null>(null);

  // Form states
  const [alias, setAlias] = useState('');
  const [cookie, setCookie] = useState('');
  const [barkKey, setBarkKey] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [formError, setFormError] = useState('');

  // Per-account action loading states
  const [checkingIds, setCheckingIds] = useState<Set<string>>(new Set());
  const [runningIds, setRunningIds] = useState<Set<string>>(new Set());

  const loadAccounts = async () => {
    try {
      const data = await api.getAccounts();
      setAccounts(data);
    } catch (e: any) {
      console.error(e);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    if (active) loadAccounts();
  }, [active, refreshTrigger]);

  useEffect(() => {
    if (active) return;
    setIsAddModalOpen(false);
    setEditAccount(null);
    setSyncModalAccount(null);
    setQuickSyncAccount(null);
    setIsConsoleModalOpen(false);
    setDeleteAccountTarget(null);
    setRunAccountTarget(null);
  }, [active]);

  const cleanCookieText = (text: string) => {
    const trimmed = text.trim();
    if (trimmed.startsWith('{') && trimmed.includes('sparklight_credential')) {
      return trimmed;
    }
    if (trimmed.includes('-H ') || trimmed.includes('-b ') || trimmed.includes('--cookie')) {
      const m = trimmed.match(/-b\s+['"]([^'"]+)['"]/i) || trimmed.match(/-H\s+['"]cookie:\s*([^'"]+)['"]/i);
      if (m) return m[1].trim();
    }
    return trimmed;
  };

  const hasSessionId = (text: string) => {
    const t = text.trim();
    if (!t) return true;
    if (t.startsWith('{') && t.includes('sparklight_credential')) return true;
    return t.includes('sessionid=') || t.includes('sessionid_ss=') || t.includes('sid_tt=') || (t.length >= 32 && /^[a-f0-9]{32,64}$/i.test(t));
  };

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    const finalCookie = cleanCookieText(cookie);
    if (!finalCookie) {
      setFormError('Cookie 为必填项');
      return;
    }
    if (!hasSessionId(finalCookie)) {
      setFormError('Cookie 中缺少关键凭证 sessionid！由于浏览器 HttpOnly 安全机制，无法直接通过 document.cookie 获取。请在 Network(网络) 面板右键任意请求「复制为 cURL」后直接粘贴进来！');
      return;
    }
    setIsSubmitting(true);
    setFormError('');
    try {
      const res = await api.createAccount({
        alias: alias.trim(),
        cookie: finalCookie,
        bark_key_override: barkKey.trim() || undefined,
      });
      toast.success(res.message || '账号创建成功');
      setIsAddModalOpen(false);
      setAlias('');
      setCookie('');
      setBarkKey('');
      loadAccounts();
      onRefresh();
    } catch (e: any) {
      setFormError(e.message || '添加账号失败');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleEdit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editAccount) return;
    setIsSubmitting(true);
    setFormError('');
    try {
      await api.updateAccount(editAccount.id, {
        alias: alias.trim() || undefined,
        cookie: cookie.trim() || undefined,
        bark_key_override: barkKey.trim() || undefined,
      });
      toast.success('账号更新成功');
      setEditAccount(null);
      loadAccounts();
      onRefresh();
    } catch (e: any) {
      setFormError(e.message || '更新账号失败');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleCheckCookie = async (id: string) => {
    setCheckingIds((prev) => new Set(prev).add(id));
    try {
      const res = await api.checkAccount(id);
      if (res.data?.is_valid) {
        toast.success(res.message);
      } else {
        toast.error(res.message);
      }
      loadAccounts();
      onRefresh();
    } catch (e: any) {
      toast.error(`检测失败: ${e.message}`);
    } finally {
      setCheckingIds((prev) => {
        const next = new Set(prev);
        next.delete(id);
        return next;
      });
    }
  };

  const handleQuickSyncSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!quickSyncAccount || !quickSyncCookie.trim()) return;
    setIsQuickSyncing(true);
    try {
      await api.updateAccount(quickSyncAccount.id, { cookie: quickSyncCookie.trim() });
      toast.success('浏览器最新 Cookie 已成功同步更新');
      setQuickSyncAccount(null);
      setQuickSyncCookie('');
      loadAccounts();
      onRefresh();
    } catch (e: any) {
      toast.error(`同步更新失败: ${e.message}`);
    } finally {
      setIsQuickSyncing(false);
    }
  };


  const getCliCommand = (targetAccId?: string) => {
    const accArg = targetAccId ? ` --account-id ${targetAccId}` : '';
    return `python3 tools/sync_douyin_cookie.py --server ${window.location.origin} --api-key ${api.getApiKey()}${accArg}`;
  };

  const handleCopyCliCommand = async (targetId?: string) => {
    const cmd = getCliCommand(targetId);
    const ok = await copyToClipboard(cmd);
    if (ok) {
      setIsCliCopied(true);
      toast.success('自动化同步命令已成功复制！');
      setTimeout(() => setIsCliCopied(false), 3000);
    }
  };


  const handleRunAccountConfirm = async () => {
    if (!runAccountTarget) return;
    const id = runAccountTarget.id;
    setRunAccountTarget(null);
    setRunningIds((prev) => new Set(prev).add(id));
    try {
      const res = await api.runAccount(id);
      if (res.data?.status === 'SUCCESS') toast.success(res.message || '账号任务正常结束');
      else if (res.data?.status === 'PARTIAL_FAILED') toast.info(res.message || '账号任务部分失败');
      else toast.error(res.message || '账号任务失败或结果未确认');
      loadAccounts();
      onRefresh();
    } catch (e: any) {
      toast.error(`执行失败: ${e.message}`);
    } finally {
      setRunningIds((prev) => {
        const next = new Set(prev);
        next.delete(id);
        return next;
      });
    }
  };

  const handleDeleteAccountConfirm = async () => {
    if (!deleteAccountTarget) return;
    const { id, alias } = deleteAccountTarget;
    setDeleteAccountTarget(null);
    try {
      await api.deleteAccount(id);
      toast.success(`账号「${alias}」已成功删除`);
      loadAccounts();
      onRefresh();
    } catch (e: any) {
      toast.error(`删除失败: ${e.message}`);
    }
  };

  const handleOpenSyncFriends = async (account: AccountDto) => {
    setSyncModalAccount(account);
    setSyncedFriends([]);
    setSelectedFriends(new Set());
    setSyncError('');
    setIsSyncing(true);
    try {
      const friends = await api.syncFriends(account.id);
      setSyncedFriends(friends);
    } catch (e: any) {
      toast.error(`获取好友失败: ${e.message}`);
    } finally {
      setIsSyncing(false);
    }
  };

  const handleToggleSelectFriend = (sec_uid: string) => {
    setSelectedFriends((prev) => {
      const next = new Set(prev);
      if (next.has(sec_uid)) next.delete(sec_uid);
      else next.add(sec_uid);
      return next;
    });
  };

  const handleSelectAllFriends = () => {
    if (selectedFriends.size === syncedFriends.length) {
      setSelectedFriends(new Set());
    } else {
      setSelectedFriends(new Set(syncedFriends.map((f) => f.sec_uid)));
    }
  };

  const handleBatchAddTargets = async () => {
    if (!syncModalAccount || selectedFriends.size === 0) return;
    setIsBatchAdding(true);
    setSyncError('');
    try {
      const targets = syncedFriends
        .filter((f) => selectedFriends.has(f.sec_uid))
        .map((f) => ({
          target_sec_uid: f.sec_uid,
          target_uid: f.uid,
          conversation_id: f.conversation_id,
          conversation_type: f.target_type || 1,
          target_nickname: f.nickname,
          target_avatar: f.avatar_url,
          spark_days: f.spark_days || 0,
          spark_desc: f.spark_desc || undefined,
          message_template: '🔥',
        }));

      const res = await api.batchCreateTargets(syncModalAccount.id, targets);
      if (!res.added_count) {
        const msg = res.message || '没有新的好友被添加';
        setSyncError(msg);
        toast.info(msg);
      } else {
        toast.success(res.message);
        setSyncModalAccount(null);
        loadAccounts();
        onRefresh();
      }
    } catch (e: any) {
      const msg = e.message || '添加失败';
      setSyncError(msg);
      toast.error(`添加失败: ${msg}`);
    } finally {
      setIsBatchAdding(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
            抖音账号管理
          </h1>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            多账号隔离运行，Cookie 采用 XChaCha20Poly1305 强加密存储并支持自动续期
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => {
              const defaultAcc = accounts[0] || null;
              setConsoleModalAccount(defaultAcc);
              setConsoleTargetAccountId(defaultAcc ? defaultAcc.id : '');
              setIsConsoleModalOpen(true);
            }}
            className="flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 transition"
          >
            <Terminal className="w-4 h-4 text-orange-500" />
            <span>自动化同步凭证助手</span>
          </button>
          <button
            onClick={() => {
              setAlias('');
              setCookie('');
              setBarkKey('');
              setFormError('');
              setIsAddModalOpen(true);
            }}
            className="flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium rounded-xl bg-orange-500 hover:bg-orange-600 active:scale-95 text-white transition shadow-sm shadow-orange-500/20"
          >
            <Plus className="w-4 h-4" />
            <span>添加账号</span>
          </button>
        </div>
      </div>

      {/* Account Cards Grid */}
      {isLoading ? (
        <div className="flex justify-center py-16">
          <Loader2 className="w-8 h-8 text-orange-500 animate-spin" />
        </div>
      ) : accounts.length === 0 ? (
        <div className="text-center py-16 rounded-2xl bg-white dark:bg-slate-900 border border-dashed border-slate-200 dark:border-slate-800 p-8">
          <Users className="w-12 h-12 text-slate-400 mx-auto mb-3" />
          <h3 className="text-sm font-semibold text-slate-800 dark:text-slate-200">暂无抖音账号</h3>
          <p className="text-xs text-slate-500 dark:text-slate-400 max-w-sm mx-auto mt-1">
            点击上方按钮填入 Cookie，系统将自动识别昵称、加密存储并建立独立会话。
          </p>
          <button
            onClick={() => setIsAddModalOpen(true)}
            className="mt-4 px-4 py-2 text-xs font-medium rounded-xl bg-orange-500 hover:bg-orange-600 text-white"
          >
            立即添加第一个账号
          </button>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {accounts.map((acc) => {
            const isValid = acc.status === 'ACTIVE';
            const isChecking = checkingIds.has(acc.id);
            const isRunning = runningIds.has(acc.id);

            return (
              <div
                key={acc.id}
                className="rounded-2xl bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800/80 p-5 shadow-sm hover:shadow-md transition flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-start justify-between gap-3 min-w-0">
                    <div className="flex items-center gap-3 min-w-0 flex-1">
                      {acc.avatar_url ? (
                        <img
                          src={acc.avatar_url}
                          alt=""
                          className="w-12 h-12 rounded-full object-cover border-2 border-slate-100 dark:border-slate-800"
                        />
                      ) : (
                        <div className="w-12 h-12 rounded-full bg-orange-100 dark:bg-orange-900/30 flex items-center justify-center font-bold text-sm text-orange-600 dark:text-orange-400 border border-orange-200 dark:border-orange-800/50">
                          {accountDisplayName(acc.nickname, acc.alias).slice(0, 1)}
                        </div>
                      )}
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2 flex-wrap min-w-0">
                          <h3 className="font-semibold text-sm text-slate-900 dark:text-slate-100 truncate max-w-[160px] sm:max-w-[220px]" title={accountDisplayName(acc.nickname, acc.alias)}>
                            {accountDisplayName(acc.nickname, acc.alias)}
                          </h3>
                          <span
                            className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold ${
                              isValid
                                ? 'bg-emerald-100 dark:bg-emerald-950/40 text-emerald-600 dark:text-emerald-400'
                                : 'bg-rose-100 dark:bg-rose-950/40 text-rose-600 dark:text-rose-400'
                            }`}
                          >
                            {isValid ? <CheckCircle2 className="w-3 h-3" /> : <AlertTriangle className="w-3 h-3" />}
                            {isValid ? '登录正常' : acc.status === 'DISABLED' ? '已停用' : '已失效'}
                          </span>
                        </div>
                        {isValid && acc.im_history_status && acc.im_history_status !== 'AVAILABLE' && (
                          <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-1 leading-snug break-words">
                            {acc.im_history_status === 'INVALID' ? '消息会话待校验，执行时重新获取' : '消息会话待刷新，执行时自动获取'}
                          </p>
                        )}
                        {!acc.nickname && (
                          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">未同步昵称</p>
                        )}
                      </div>
                    </div>

                    <div className="flex items-center gap-1 shrink-0">
                      {/* Browser DevTools Console Injector Modal */}
                      <button
                        onClick={() => {
                          setConsoleModalAccount(acc);
                          setConsoleTargetAccountId(acc.id);
                          setIsConsoleModalOpen(true);
                        }}
                        className="p-1.5 text-blue-500 hover:text-blue-600 rounded-lg hover:bg-blue-50 dark:hover:bg-blue-950/30 transition"
                        title="控制台一键提取与同步"
                      >
                        <Terminal className="w-3.5 h-3.5" />
                      </button>
                      {/* One-click sync from browser cookie */}
                      <button
                        onClick={() => {
                          setQuickSyncAccount(acc);
                          setQuickSyncCookie('');
                        }}
                        className="p-1.5 text-orange-500 hover:text-orange-600 rounded-lg hover:bg-orange-50 dark:hover:bg-orange-950/30 transition"
                        title="联动同步浏览器最新 Cookie"
                      >
                        <Link2 className="w-3.5 h-3.5" />
                      </button>
                      <button
                        onClick={() => {
                          setEditAccount(acc);
                          setAlias(acc.alias);
                          setCookie('');
                          setBarkKey(acc.bark_key_override || '');
                          setFormError('');
                        }}
                        className="p-1.5 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800"
                        title="编辑账号"
                      >
                        <Edit3 className="w-3.5 h-3.5" />
                      </button>
                      <button
                        onClick={() => setDeleteAccountTarget(acc)}
                        className="p-1.5 text-slate-400 hover:text-rose-500 rounded-lg hover:bg-rose-50 dark:hover:bg-rose-950/30"
                        title="删除账号"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>

                  <div className="mt-4 space-y-1.5 text-xs text-slate-600 dark:text-slate-300 bg-slate-50 dark:bg-slate-800/40 p-3 rounded-xl">
                    <div className="flex justify-between items-center">
                      <span className="text-slate-400 text-[11px]">密文Cookie:</span>
                      <span className="font-mono text-[11px] text-slate-500 truncate max-w-[200px]">
                        {acc.masked_cookie || '无'}
                      </span>
                    </div>
                    {acc.uid && (
                      <div className="flex justify-between items-center">
                        <span className="text-slate-400 text-[11px]">抖音 UID:</span>
                        <span className="font-mono text-[11px]">{acc.uid}</span>
                      </div>
                    )}
                    <div className="flex justify-between items-center">
                      <span className="text-slate-400 text-[11px]">续火花目标:</span>
                      <span className="font-medium text-orange-600 dark:text-orange-400">
                        {acc.active_targets_count} / {acc.targets_count} 个启用
                      </span>
                    </div>
                    {acc.bark_key_override && (
                      <div className="flex justify-between items-center">
                        <span className="text-slate-400 text-[11px]">独立 Bark:</span>
                        <span className="text-[11px] text-emerald-600 flex items-center gap-1">
                          <Bell className="w-3 h-3" /> 已指定专属推送
                        </span>
                      </div>
                    )}
                    <div className="flex justify-between items-center">
                      <span className="text-slate-400 text-[11px]">最后检测:</span>
                      <span className="text-[11px] text-slate-400">
                        {acc.last_checked_at ? new Date(acc.last_checked_at).toLocaleString() : '未检测'}
                      </span>
                    </div>
                  </div>
                </div>

                <div className="mt-4 pt-3 border-t border-slate-100 dark:border-slate-800/80 flex flex-wrap sm:flex-nowrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2 flex-wrap sm:flex-nowrap shrink-0">
                    <button
                      onClick={() => handleCheckCookie(acc.id)}
                      disabled={isChecking}
                      className="flex items-center gap-1 px-2.5 py-1.5 text-xs font-medium rounded-lg border border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition"
                    >
                      <RefreshCw className={`w-3 h-3 ${isChecking ? 'animate-spin' : ''}`} />
                      <span>检测有效性</span>
                    </button>

                    <button
                      onClick={() => handleOpenSyncFriends(acc)}
                      className="flex items-center gap-1 px-2.5 py-1.5 text-xs font-medium rounded-lg border border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition"
                    >
                      <Share2 className="w-3 h-3 text-blue-500" />
                      <span>同步好友</span>
                    </button>
                  </div>

                  <button
                    onClick={() => setRunAccountTarget(acc)}
                    disabled={isRunning || !isValid}
                    className="flex items-center gap-1 px-3 py-1.5 text-xs font-medium rounded-lg bg-orange-500 hover:bg-orange-600 text-white transition disabled:opacity-40"
                  >
                    {isRunning ? <Loader2 className="w-3 h-3 animate-spin" /> : <Play className="w-3 h-3 fill-current" />}
                    <span>续火花</span>
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Add Account Modal */}
      {isAddModalOpen && (
        <ModalPortal>
          <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/60 backdrop-blur-sm p-4 overflow-y-auto">
          <div className="relative w-full max-w-lg rounded-2xl bg-white dark:bg-slate-900 p-6 shadow-2xl border border-slate-200 dark:border-slate-800 animate-in fade-in zoom-in-95 duration-150">
            <button
              onClick={() => setIsAddModalOpen(false)}
              className="absolute right-4 top-4 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200"
            >
              <X className="w-5 h-5" />
            </button>

            <h3 className="text-base font-bold text-slate-900 dark:text-slate-100 mb-1">添加抖音账号</h3>
            <p className="text-xs text-slate-500 dark:text-slate-400 mb-4">
              填入 Cookie 后系统将自动检测、自动识别昵称并加密隔离存储
            </p>

            <form onSubmit={handleCreate} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                  账号别名 / 备注 (可选，留空自动获取抖音昵称)
                </label>
                <input
                  type="text"
                  value={alias}
                  onChange={(e) => setAlias(e.target.value)}
                  placeholder="留空则自动读取抖音账号真实昵称"
                  className="w-full px-3 py-2 text-xs rounded-xl border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 focus:ring-2 focus:ring-orange-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                  抖音 Cookie 明文 *
                </label>
                <textarea
                  required
                  rows={4}
                  value={cookie}
                  onChange={(e) => setCookie(cleanCookieText(e.target.value))}
                  placeholder="直接粘贴油猴脚本一键复制的凭证对象，或粘贴 Cookie / cURL 命令"
                  className="w-full px-3 py-2 text-xs font-mono rounded-xl border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 focus:ring-2 focus:ring-orange-500 focus:outline-none"
                />
                {cookie.trim() && !hasSessionId(cookie) && (
                  <div className="mt-2 p-2.5 rounded-xl bg-amber-50 dark:bg-amber-950/30 border border-amber-300 dark:border-amber-800 text-amber-800 dark:text-amber-300 text-xs">
                    <p className="font-semibold flex items-center gap-1.5 mb-1">
                      <AlertTriangle className="w-3.5 h-3.5 text-amber-500" />
                      <span>未检测到关键凭证 sessionid</span>
                    </p>
                    <p className="text-[11px] leading-relaxed text-slate-600 dark:text-slate-400">
                      因浏览器 <strong>HttpOnly</strong> 安全机制，直接通过控制台 <code>document.cookie</code> 获取的内容无法包含 <code>sessionid</code>。<br/>
                      <strong>极速解决</strong>：在已登录抖音页面按 F12 ➔ Network (网络) 标签页 ➔ 刷新或点任一私信 ➔ 右键任意请求 ➔ <strong>复制为 cURL</strong> ➔ 直接粘贴到此处，系统将秒级自动提取！
                    </p>
                  </div>
                )}
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                  独立 Bark 推送 Key (可选)
                </label>
                <input
                  type="text"
                  value={barkKey}
                  onChange={(e) => setBarkKey(e.target.value)}
                  placeholder="为空时使用系统全局默认 Bark Key"
                  className="w-full px-3 py-2 text-xs rounded-xl border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 focus:ring-2 focus:ring-orange-500 focus:outline-none"
                />
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
                  disabled={isSubmitting}
                  className="flex-1 flex items-center justify-center gap-1.5 px-4 py-2 text-xs font-medium rounded-xl bg-orange-500 hover:bg-orange-600 text-white disabled:opacity-50"
                >
                  {isSubmitting ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Plus className="w-3.5 h-3.5" />}
                  <span>保存并检测</span>
                </button>
              </div>
            </form>
          </div>
          </div>
        </ModalPortal>
      )}

      {/* Quick Sync Modal for refreshing from browser */}
      {quickSyncAccount && (
        <ModalPortal>
          <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/60 backdrop-blur-sm p-4 overflow-y-auto">
          <div className="relative w-full max-w-md rounded-2xl bg-white dark:bg-slate-900 p-6 shadow-2xl border border-slate-200 dark:border-slate-800 animate-in fade-in zoom-in-95 duration-150">
            <button
              onClick={() => setQuickSyncAccount(null)}
              className="absolute right-4 top-4 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200"
            >
              <X className="w-5 h-5" />
            </button>

            <div className="flex items-center gap-2.5 mb-2">
              <div className="p-2 rounded-xl bg-orange-500/10 text-orange-500">
                <Link2 className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-base font-bold text-slate-900 dark:text-slate-100">
                  联动更新浏览器凭证: {quickSyncAccount.alias}
                </h3>
                <p className="text-xs text-slate-500">一键粘贴或同步在浏览器中新获取的有效 Cookie</p>
              </div>
            </div>

            <form onSubmit={handleQuickSyncSubmit} className="space-y-4 mt-3">
              <div>
                <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                  新 Cookie 字符串
                </label>
                <textarea
                  required
                  rows={4}
                  value={quickSyncCookie}
                  onChange={(e) => setQuickSyncCookie(cleanCookieText(e.target.value))}
                  placeholder="直接粘贴油猴脚本一键复制的凭证对象，或粘贴 Cookie / cURL 命令"
                  className="w-full px-3 py-2 text-xs font-mono rounded-xl border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 focus:ring-2 focus:ring-orange-500 focus:outline-none"
                />
                {quickSyncCookie.trim() && !hasSessionId(quickSyncCookie) && (
                  <div className="mt-2 p-2.5 rounded-xl bg-amber-50 dark:bg-amber-950/30 border border-amber-300 dark:border-amber-800 text-amber-800 dark:text-amber-300 text-xs">
                    <p className="font-semibold flex items-center gap-1.5 mb-1">
                      <AlertTriangle className="w-3.5 h-3.5 text-amber-500" />
                      <span>未检测到 sessionid 凭证</span>
                    </p>
                    <p className="text-[11px] text-slate-600 dark:text-slate-400">
                      请在已登录页面 Network (网络) 面板右键任意请求 ➔ <strong>复制为 cURL</strong> ➔ 直接粘贴进来即可！
                    </p>
                  </div>
                )}
              </div>

              <div className="flex gap-2.5 pt-1">
                <button
                  type="button"
                  onClick={() => setQuickSyncAccount(null)}
                  className="flex-1 px-4 py-2 text-xs font-medium rounded-xl border border-slate-200 dark:border-slate-800 hover:bg-slate-100 dark:hover:bg-slate-800"
                >
                  取消
                </button>
                <button
                  type="submit"
                  disabled={isQuickSyncing}
                  className="flex-1 flex items-center justify-center gap-1.5 px-4 py-2 text-xs font-medium rounded-xl bg-orange-500 hover:bg-orange-600 text-white disabled:opacity-50"
                >
                  {isQuickSyncing ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <RefreshCw className="w-3.5 h-3.5" />}
                  <span>更新并保存</span>
                </button>
              </div>
            </form>
          </div>
          </div>
        </ModalPortal>
      )}

      {/* Edit Account Modal */}
      {editAccount && (
        <ModalPortal>
          <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/60 backdrop-blur-sm p-4 overflow-y-auto">
          <div className="relative w-full max-w-lg rounded-2xl bg-white dark:bg-slate-900 p-6 shadow-2xl border border-slate-200 dark:border-slate-800 animate-in fade-in zoom-in-95 duration-150">
            <button
              onClick={() => setEditAccount(null)}
              className="absolute right-4 top-4 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200"
            >
              <X className="w-5 h-5" />
            </button>

            <h3 className="text-base font-bold text-slate-900 dark:text-slate-100 mb-1">
              编辑账号: {editAccount.alias}
            </h3>
            <p className="text-xs text-slate-500 dark:text-slate-400 mb-4">
              可修改别名或重新填入新的有效 Cookie 进行续期
            </p>

            <form onSubmit={handleEdit} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                  账号别名
                </label>
                <input
                  type="text"
                  value={alias}
                  onChange={(e) => setAlias(e.target.value)}
                  className="w-full px-3 py-2 text-xs rounded-xl border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 focus:ring-2 focus:ring-orange-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                  更新 Cookie (不修改请留空)
                </label>
                <textarea
                  rows={3}
                  value={cookie}
                  onChange={(e) => setCookie(cleanCookieText(e.target.value))}
                  placeholder="可直接粘贴油猴脚本复制的全量凭证对象，或纯 Cookie"
                  className="w-full px-3 py-2 text-xs font-mono rounded-xl border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 focus:ring-2 focus:ring-orange-500 focus:outline-none"
                />
                {cookie.trim() && !hasSessionId(cookie) && (
                  <div className="mt-2 p-2.5 rounded-xl bg-amber-50 dark:bg-amber-950/30 border border-amber-300 dark:border-amber-800 text-amber-800 dark:text-amber-300 text-xs">
                    <p className="font-semibold flex items-center gap-1.5 mb-1">
                      <AlertTriangle className="w-3.5 h-3.5 text-amber-500" />
                      <span>未检测到 sessionid 凭证</span>
                    </p>
                    <p className="text-[11px] text-slate-600 dark:text-slate-400">
                      请在已登录页面 Network (网络) 面板右键任意请求 ➔ <strong>复制为 cURL</strong> ➔ 直接粘贴进来即可！
                    </p>
                  </div>
                )}
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                  独立 Bark 推送 Key
                </label>
                <input
                  type="text"
                  value={barkKey}
                  onChange={(e) => setBarkKey(e.target.value)}
                  placeholder="清空则退回全局默认推送 Key"
                  className="w-full px-3 py-2 text-xs rounded-xl border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 focus:ring-2 focus:ring-orange-500 focus:outline-none"
                />
              </div>

              {formError && <p className="text-xs text-rose-500">{formError}</p>}

              <div className="flex gap-2.5 pt-2">
                <button
                  type="button"
                  onClick={() => setEditAccount(null)}
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
                  <span>更新信息</span>
                </button>
              </div>
            </form>
          </div>
          </div>
        </ModalPortal>
      )}

      {/* Sync Friends Drawer / Modal */}
      {syncModalAccount && (
        <ModalPortal>
          <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/60 backdrop-blur-sm p-4 overflow-y-auto">
          <div className="relative w-full max-w-xl max-h-[85vh] rounded-2xl bg-white dark:bg-slate-900 p-6 shadow-2xl border border-slate-200 dark:border-slate-800 flex flex-col">
            <button
              onClick={() => setSyncModalAccount(null)}
              className="absolute right-4 top-4 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200"
            >
              <X className="w-5 h-5" />
            </button>

            <div>
              <h3 className="text-base font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
                <Share2 className="w-4 h-4 text-blue-500" />
                从「{syncModalAccount.alias}」同步好友
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                实时从抖音 IM 好友关系链拉取，可多选批量导入为续火花对象
              </p>
            </div>

            <div className="my-4 flex-1 overflow-y-auto space-y-2 pr-1 border-t border-b border-slate-100 dark:border-slate-800/80 py-3">
              {isSyncing ? (
                <div className="py-12 flex flex-col items-center justify-center gap-2">
                  <Loader2 className="w-6 h-6 text-orange-500 animate-spin" />
                  <span className="text-xs text-slate-400">正在向抖音接口拉取好友列表...</span>
                </div>
              ) : syncedFriends.length === 0 ? (
                <div className="py-12 text-center text-xs text-slate-400">
                  未获取到好友（可在“续火花目标”页通过下拉选择或输入添加）
                </div>
              ) : (
                syncedFriends.map((friend) => {
                  const isChecked = selectedFriends.has(friend.sec_uid);
                  return (
                    <div
                      key={friend.sec_uid}
                      onClick={() => handleToggleSelectFriend(friend.sec_uid)}
                      className={`flex items-center justify-between p-2.5 rounded-xl border cursor-pointer transition ${
                        isChecked
                          ? 'border-orange-500/50 bg-orange-50/50 dark:bg-orange-950/20'
                          : 'border-slate-100 dark:border-slate-800 hover:bg-slate-50 dark:hover:bg-slate-800/50'
                      }`}
                    >
                      <div className="flex items-center gap-3">
                        <CustomCheckbox
                          checked={isChecked}
                          onChange={() => handleToggleSelectFriend(friend.sec_uid)}
                        />
                        {friend.avatar_url ? (
                          <img src={friend.avatar_url} alt="" className="w-8 h-8 rounded-full object-cover" />
                        ) : (
                          <div className="w-8 h-8 rounded-full bg-slate-200 dark:bg-slate-700 flex items-center justify-center text-xs font-bold">
                            {friend.nickname.slice(0, 1)}
                          </div>
                        )}
                        <div>
                          <div className="flex items-center gap-1.5 flex-wrap">
                            <p className="text-xs font-semibold text-slate-800 dark:text-slate-200 whitespace-nowrap">
                              {formatDisplayName(friend.nickname, friend.remark_name)}
                            </p>
                            {friend.target_type === 2 && (
                              <span className="px-1.5 py-0.5 rounded text-[10px] bg-blue-100 dark:bg-blue-950/60 text-blue-700 dark:text-blue-300 font-medium">
                                👥 群聊
                              </span>
                            )}
                          </div>
                          <p className="text-[10px] text-slate-400 font-mono">
                            {friend.target_type === 2 ? `群ID: ${friend.conversation_id || friend.sec_uid}` : `${friend.sec_uid.slice(0, 24)}...`}
                          </p>
                        </div>
                      </div>
                      {(() => {
                        const sparkInfo = parseSparkStatus(friend.spark_days, friend.spark_desc);
                        return (
                          <div className={`flex items-center gap-1.5 text-xs font-medium px-2 py-0.5 rounded-lg border ${sparkInfo.badgeClass}`}>
                            <Sparkles className="w-3.5 h-3.5" />
                            <span>{sparkInfo.label}</span>
                          </div>
                        );
                      })()}
                    </div>
                  );
                })
              )}
            </div>

            {syncError && (
              <p className="mb-2 text-xs text-rose-500">{syncError}</p>
            )}
            <div className="flex items-center justify-between pt-1">
              {syncedFriends.length > 0 && (
                <button
                  type="button"
                  onClick={handleSelectAllFriends}
                  className="text-xs font-medium text-orange-600 dark:text-orange-400 hover:underline"
                >
                  {selectedFriends.size === syncedFriends.length ? '取消全选' : '全选所有好友'}
                </button>
              )}
              <div className="flex gap-2 ml-auto">
                <button
                  type="button"
                  onClick={() => setSyncModalAccount(null)}
                  className="px-3.5 py-1.5 text-xs font-medium rounded-xl border border-slate-200 dark:border-slate-800"
                >
                  关闭
                </button>
                <button
                  type="button"
                  onClick={handleBatchAddTargets}
                  disabled={isBatchAdding || selectedFriends.size === 0}
                  className="flex items-center gap-1.5 px-4 py-1.5 text-xs font-medium rounded-xl bg-orange-500 hover:bg-orange-600 text-white disabled:opacity-40"
                >
                  {isBatchAdding ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Plus className="w-3.5 h-3.5" />}
                  <span>导入选中的 {selectedFriends.size} 位好友</span>
                </button>
              </div>
            </div>
          </div>
          </div>
        </ModalPortal>
      )}

      {/* Browser DevTools Console Injector Modal */}
      {isConsoleModalOpen && (
        <ModalPortal>
          <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/60 backdrop-blur-sm p-4 overflow-y-auto">
          <div className="relative w-full max-w-2xl max-h-[90vh] my-auto rounded-2xl bg-white dark:bg-slate-900 p-6 shadow-2xl border border-slate-200 dark:border-slate-800 flex flex-col animate-in fade-in zoom-in-95 duration-150">
            <button
              onClick={() => setIsConsoleModalOpen(false)}
              className="absolute right-4 top-4 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200"
            >
              <X className="w-5 h-5" />
            </button>

            <div className="flex items-center gap-3 mb-4">
              <div className="p-2.5 rounded-xl bg-orange-500/10 text-orange-500">
                <Terminal className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-base font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
                  全自动 Cookie 凭证同步助手
                </h3>
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  突破手动复制 cURL 瓶颈 · 提供浏览器扩展一键同步、本机助手及控制台脚本
                </p>
              </div>
            </div>

            {/* Method Tabs */}
            <div className="flex items-center gap-1.5 mb-4 p-1 rounded-xl bg-slate-100 dark:bg-slate-800/80 border border-slate-200/60 dark:border-slate-700/60">
              <button
                type="button"
                onClick={() => setSyncGuideTab('tampermonkey')}
                className={`flex-1 py-1.5 px-3 rounded-lg text-xs font-semibold transition ${
                  syncGuideTab === 'tampermonkey'
                    ? 'bg-white dark:bg-slate-900 text-orange-600 dark:text-orange-400 shadow-sm'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
                }`}
              >
                🐵 油猴全自动脚本 (强烈推荐 · 100% 免抓包与风控)
              </button>
              <button
                type="button"
                onClick={() => setSyncGuideTab('cli')}
                className={`py-1.5 px-4 rounded-lg text-xs font-semibold transition ${
                  syncGuideTab === 'cli'
                    ? 'bg-white dark:bg-slate-900 text-orange-600 dark:text-orange-400 shadow-sm'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
                }`}
              >
                ⚡ 本机 Python 助手
              </button>
            </div>

            {/* Target Account Selector */}
            {accounts.length > 0 && (
              <div className="mb-4 p-3 rounded-xl bg-slate-50 dark:bg-slate-800/40 border border-slate-200/80 dark:border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <span className="text-xs font-medium text-slate-700 dark:text-slate-300">
                  同步绑定目标账号:
                </span>
                <div className="flex flex-wrap gap-1.5">
                  {accounts.map((acc) => {
                    const isSelected = (consoleTargetAccountId || consoleModalAccount?.id) === acc.id;
                    return (
                      <button
                        key={acc.id}
                        type="button"
                        onClick={() => {
                          setConsoleTargetAccountId(acc.id);
                          setConsoleModalAccount(acc);
                        }}
                        className={`px-2.5 py-1 text-xs rounded-lg font-medium transition ${
                          isSelected
                            ? 'bg-orange-500 text-white shadow-sm'
                            : 'bg-white dark:bg-slate-800 text-slate-600 dark:text-slate-300 border border-slate-200 dark:border-slate-700 hover:bg-slate-100'
                        }`}
                      >
                        {accountDisplayName(acc.nickname, acc.alias)}
                      </button>
                    );
                  })}
                </div>
              </div>
            )}

            {syncGuideTab === 'tampermonkey' && (
              <div className="space-y-3.5 mb-4 text-xs">
                <div className="p-3.5 rounded-xl bg-orange-50/70 dark:bg-orange-950/20 border border-orange-200/80 dark:border-orange-900/40">
                  <div className="font-bold text-orange-700 dark:text-orange-300 flex items-center justify-between mb-1.5">
                    <span>⚡ 一键提取全量凭证（含 HttpOnly 与 Guard 签名私钥/票据）</span>
                    <button
                      type="button"
                      onClick={() => {
                        copyToClipboard(TAMPERMONKEY_SCRIPT);
                        toast.success('油猴脚本代码已复制到剪贴板！');
                      }}
                      className="flex items-center gap-1 px-2.5 py-1 text-xs font-semibold rounded-lg bg-orange-500 hover:bg-orange-600 text-white shadow-sm active:scale-95 transition"
                    >
                      <Copy className="w-3 h-3" />
                      <span>复制油猴脚本代码</span>
                    </button>
                  </div>
                  <p className="text-[11px] text-slate-600 dark:text-slate-400 leading-relaxed">
                    通过 Tampermonkey (油猴) 扩展，在已登录的抖音页面右下角自动生成浮动胶囊按钮。点击即可秒级全自动抓取完整 Cookie 与官方 Guard 签名私钥，<strong>100% 纯本地复制，零抓包、零上传、免除风控掉线</strong>！
                  </p>
                </div>

                <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-800/40 border border-slate-200/60 dark:border-slate-800 space-y-2.5">
                  <div className="font-bold text-slate-800 dark:text-slate-200 text-xs">3 步极简使用流程:</div>
                  <ol className="list-decimal list-inside space-y-1.5 text-[11px] text-slate-600 dark:text-slate-400">
                    <li>在浏览器安装 <strong>Tampermonkey</strong> 或 <strong>ScriptCat</strong> 扩展程序；</li>
                    <li>在扩展中新建脚本，将上方<strong>「油猴脚本代码」</strong>粘贴并保存；</li>
                    <li>打开或刷新已登录的抖音页面 (<code>douyin.com</code>)，点击页面右下角出现的<strong>「⚡ 复制 SparkLight 全量凭证」</strong>胶囊按钮，返回本系统直接粘贴即可！</li>
                  </ol>
                </div>
              </div>
            )}

            {syncGuideTab === 'cli' && (
              <div className="space-y-3 mb-4 text-xs">
                <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-800/40 border border-slate-200/60 dark:border-slate-800">
                  <div className="font-bold text-slate-800 dark:text-slate-200 mb-1">
                    在本地终端运行单行命令提取并同步：
                  </div>
                  <p className="text-[11px] text-slate-500 mb-3">
                    直接读取本机浏览器已登录的 Cookies 数据库并在内存中安全解密上报，全程不打印任何凭据：
                  </p>
                  <div className="flex items-center justify-between gap-2 p-2 rounded-lg bg-slate-950 font-mono text-[11px] text-slate-200">
                    <span className="truncate">{getCliCommand(consoleTargetAccountId || consoleModalAccount?.id)}</span>
                    <button
                      type="button"
                      onClick={() => handleCopyCliCommand(consoleTargetAccountId || consoleModalAccount?.id)}
                      className="flex items-center gap-1 px-2.5 py-1 text-xs font-semibold rounded bg-orange-500 hover:bg-orange-600 text-white shrink-0 active:scale-95 transition"
                    >
                      {isCliCopied ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                      <span>{isCliCopied ? '已复制' : '复制命令'}</span>
                    </button>
                  </div>
                </div>
              </div>
            )}

            </div>
          </div>
        </ModalPortal>
      )}
      {/* Custom Confirmation Modals */}
      <ConfirmModal
        isOpen={Boolean(deleteAccountTarget)}
        title="确认删除账号"
        description={`确定删除账号「${deleteAccountTarget?.alias}」吗？关联的所有续火花目标也将被一同移除。`}
        confirmText="删除账号"
        isDanger={true}
        onConfirm={handleDeleteAccountConfirm}
        onCancel={() => setDeleteAccountTarget(null)}
      />

      <ConfirmModal
        isOpen={Boolean(runAccountTarget)}
        title="立即触发续火花"
        description={`确定立即对账号「${runAccountTarget?.alias}」旗下的所有已启用续火花目标执行一次消息互动吗？`}
        confirmText="立即执行"
        onConfirm={handleRunAccountConfirm}
        onCancel={() => setRunAccountTarget(null)}
      />
    </div>
  );
};
