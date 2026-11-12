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
  LogIn,
  ShieldCheck,
  MessageSquareText,
  KeyRound,
  Upload,
  Download,
  Copy,
  Smartphone,
  QrCode,
  ArrowLeft,
} from 'lucide-react';
import { api, AccountLoginChallenge, AccountLoginDelivery } from '../api/client';
import { AccountDto, DouyinFriend } from '../types';
import { useToast } from '../components/ui/Toast';
import { ConfirmModal } from '../components/ui/ConfirmModal';
import { CustomCheckbox } from '../components/ui/CustomCheckbox';
import { ModalPortal } from '../components/ui/ModalPortal';
import { parseSparkStatus } from '../utils/spark';
import { accountDisplayName, formatDisplayName } from '../utils/displayName';
import { copyToClipboard } from '../utils/clipboard';
import { formatBeijingDateTime } from '../utils/datetime';


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
  const [isNativeImportOpen, setIsNativeImportOpen] = useState(false);
  const [nativeImportAccount, setNativeImportAccount] = useState<AccountDto | null>(null);
  const [nativeImportText, setNativeImportText] = useState('');
  const [nativeImportFileName, setNativeImportFileName] = useState('');
  const [nativeImportError, setNativeImportError] = useState('');
  const [isNativeImporting, setIsNativeImporting] = useState(false);
  const [editAccount, setEditAccount] = useState<AccountDto | null>(null);
  const [syncModalAccount, setSyncModalAccount] = useState<AccountDto | null>(null);
  const [syncedFriends, setSyncedFriends] = useState<DouyinFriend[]>([]);
  const [selectedFriends, setSelectedFriends] = useState<Set<string>>(new Set());
  const [isSyncing, setIsSyncing] = useState(false);
  const [isBatchAdding, setIsBatchAdding] = useState(false);
  const [syncError, setSyncError] = useState('');

  // App 原生二维码登录会话：账号为空表示新增账号
  const [loginTarget, setLoginTarget] = useState<{ accountId?: string; alias: string } | null>(null);

  // App 原生登录（手机号短信验证码 / 手机号密码）
  const [nativeLoginMode, setNativeLoginMode] = useState<'sms' | 'password'>('sms');
  const [nativeMobile, setNativeMobile] = useState('');
  const [nativeSmsCode, setNativeSmsCode] = useState('');
  const [nativePassword, setNativePassword] = useState('');
  const [phoneLoginId, setPhoneLoginId] = useState('');
  const [phoneMobileMasked, setPhoneMobileMasked] = useState('');
  const [smsSending, setSmsSending] = useState(false);
  const [smsCooldown, setSmsCooldown] = useState(0);
  const [nativeSubmitting, setNativeSubmitting] = useState(false);
  const [nativeLoginError, setNativeLoginError] = useState('');
  const [secondVerifyChallenge, setSecondVerifyChallenge] = useState<Extract<AccountLoginChallenge, { kind: 'two_step' }> | null>(null);
  const [selectedVerifyWay, setSelectedVerifyWay] = useState('');
  const [secondVerifyCode, setSecondVerifyCode] = useState('');
  const [secondVerifyPassword, setSecondVerifyPassword] = useState('');
  const [secondVerifyDelivery, setSecondVerifyDelivery] = useState<AccountLoginDelivery | null>(null);
  const [secondVerifyPreparing, setSecondVerifyPreparing] = useState(false);
  const [secondVerifyCooldown, setSecondVerifyCooldown] = useState(0);
  const [secondVerifyHint, setSecondVerifyHint] = useState('');
  const [secondVerifyPolling, setSecondVerifyPolling] = useState(false);

  // Custom Confirm Dialog States
  const [deleteAccountTarget, setDeleteAccountTarget] = useState<AccountDto | null>(null);
  const [runAccountTarget, setRunAccountTarget] = useState<AccountDto | null>(null);

  // Form states
  const [alias, setAlias] = useState('');
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
    setLoginTarget(null);
    setDeleteAccountTarget(null);
    setRunAccountTarget(null);
  }, [active]);

  useEffect(() => {
    if (smsCooldown <= 0) return;
    const timer = window.setInterval(() => {
      setSmsCooldown((current) => Math.max(0, current - 1));
    }, 1000);
    return () => window.clearInterval(timer);
  }, [smsCooldown]);

  useEffect(() => {
    if (secondVerifyCooldown <= 0) return;
    const timer = window.setInterval(() => {
      setSecondVerifyCooldown((current) => Math.max(0, current - 1));
    }, 1000);
    return () => window.clearInterval(timer);
  }, [secondVerifyCooldown]);

  const isQrVerifyWay = (way: string) =>
    way === 'qr_code_verify' ||
    way === 'scan_qrcode_verify' ||
    way === 'face_verify' ||
    way === 'qr_code_face_verify' ||
    way === 'identity_verify';

  const isPushVerifyWay = (way: string) =>
    way === 'push_verify' || way === 'mobile_push_verify' || way === 'aweme_push_verify';

  const isUpSmsVerifyWay = (way: string) =>
    way === 'mobile_up_sms_verify' || way === 'assist_mobile_up_sms_verify';

  const isDownSmsVerifyWay = (way: string) =>
    way === 'mobile_sms_verify' ||
    way === 'assist_mobile_sms_verify' ||
    way === 'mobile_sms_check_or_verify' ||
    way === 'mobile_voice_sms_verify' ||
    way === 'assist_mobile_voice_sms_verify';

  const resetSecondVerifyState = () => {
    setSecondVerifyChallenge(null);
    setSelectedVerifyWay('');
    setSecondVerifyCode('');
    setSecondVerifyPassword('');
    setSecondVerifyDelivery(null);
    setSecondVerifyPreparing(false);
    setSecondVerifyCooldown(0);
    setSecondVerifyHint('');
    setSecondVerifyPolling(false);
  };

  const completeLoginSuccess = (nickname?: string, webReady?: boolean, message?: string) => {
    resetSecondVerifyState();
    setIsAddModalOpen(false);
    setLoginTarget(null);
    setNativePassword('');
    loadAccounts();
    onRefresh();
    if (webReady === false) {
      toast.info(`账号「${nickname || alias.trim() || '抖音账号'}」已登录，发送材料待后台自动恢复`);
    } else {
      toast.success(message || `账号「${nickname || alias.trim() || '抖音账号'}」登录成功`);
    }
  };

  const handlePrepareSecondVerify = async (loginId: string, way: string, silent = false) => {
    if (!loginId || !way) return;
    setSecondVerifyPreparing(true);
    if (!silent) setNativeLoginError('');
    try {
      const res = isUpSmsVerifyWay(way)
        ? await api.prepareAccountLoginUpSms(loginId, way)
        : await api.sendAccountLoginVerificationCode(loginId, way);
      if (res.data.delivery) {
        setSecondVerifyDelivery(res.data.delivery);
      }
      if (res.message) {
        setSecondVerifyHint(res.message);
      }
      if (isDownSmsVerifyWay(way)) {
        setSecondVerifyCooldown(60);
      }
      if (isQrVerifyWay(way) || isPushVerifyWay(way)) {
        setSecondVerifyPolling(true);
      }
    } catch (err: any) {
      setNativeLoginError(err.message || '准备安全验证失败');
    } finally {
      setSecondVerifyPreparing(false);
    }
  };

  const enterSecondVerifyStep = (
    loginId: string,
    challenge: Extract<AccountLoginChallenge, { kind: 'two_step' }>,
    message?: string,
  ) => {
    setPhoneLoginId(loginId);
    setSecondVerifyChallenge(challenge);
    setNativeLoginError('');
    setSecondVerifyCode('');
    setSecondVerifyPassword('');
    setSecondVerifyDelivery(null);
    setSecondVerifyPolling(false);
    setSecondVerifyHint(message || challenge.scene_description || '请完成安全身份核验以继续登录');
    const firstWay =
      challenge.ways.find((w) => w.supported)?.kind || challenge.ways[0]?.kind || '';
    setSelectedVerifyWay(firstWay);
    if (isUpSmsVerifyWay(firstWay) || isQrVerifyWay(firstWay)) {
      void handlePrepareSecondVerify(loginId, firstWay, true);
    }
  };

  useEffect(() => {
    if (!isAddModalOpen || !secondVerifyChallenge || !secondVerifyPolling || !phoneLoginId || !selectedVerifyWay) {
      return;
    }
    if (!isQrVerifyWay(selectedVerifyWay) && !isPushVerifyWay(selectedVerifyWay)) {
      return;
    }
    let cancelled = false;
    let inFlight = false;
    const timer = window.setInterval(async () => {
      if (inFlight || nativeSubmitting) return;
      inFlight = true;
      try {
        const res = await api.submitAccountLoginVerification(phoneLoginId, {
          way: selectedVerifyWay,
        });
        if (cancelled) return;
        if (res.data.done) {
          setSecondVerifyPolling(false);
          completeLoginSuccess(res.data.nickname, res.data.web_ready, res.message);
        } else if (res.message) {
          setSecondVerifyHint(res.message);
        }
      } catch (err: any) {
        if (!cancelled) {
          setSecondVerifyPolling(false);
          setNativeLoginError(err.message || '安全验证轮询中断');
        }
      } finally {
        inFlight = false;
      }
    }, 2500);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [isAddModalOpen, secondVerifyChallenge, secondVerifyPolling, phoneLoginId, selectedVerifyWay, nativeSubmitting]);

  const openNativeLoginModal = (target?: { accountId?: string; alias?: string }) => {
    setLoginTarget({ accountId: target?.accountId, alias: target?.alias || '' });
    setAlias(target?.alias || '');
    setNativeLoginMode('sms');
    setNativeMobile('');
    setNativeSmsCode('');
    setNativePassword('');
    setPhoneLoginId('');
    setPhoneMobileMasked('');
    setSmsSending(false);
    setNativeSubmitting(false);
    setNativeLoginError('');
    resetSecondVerifyState();
    setIsAddModalOpen(true);
  };

  const handleSendPhoneCode = async () => {
    const cleanMobile = nativeMobile.trim();
    if (!cleanMobile) {
      setNativeLoginError('请输入 11 位中国大陆手机号');
      return;
    }
    setSmsSending(true);
    setNativeLoginError('');
    try {
      const res = await api.startPhoneLogin({
        account_id: loginTarget?.accountId,
        alias: alias.trim() || loginTarget?.alias || undefined,
        mobile: cleanMobile,
      });
      setPhoneLoginId(res.data.login_id);
      setPhoneMobileMasked(res.data.mobile_masked);
      setSmsCooldown(60);
      toast.success(res.message || `验证码已发送至 ${res.data.mobile_masked}`);
    } catch (e: any) {
      setNativeLoginError(e.message || '发送短信验证码失败');
    } finally {
      setSmsSending(false);
    }
  };

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    setNativeLoginError('');
    const cleanMobile = nativeMobile.trim();
    if (!cleanMobile) {
      setNativeLoginError('请输入 11 位中国大陆手机号');
      return;
    }
    if (nativeLoginMode === 'sms') {
      if (!phoneLoginId) {
        setNativeLoginError('请先点击「获取验证码」发送短信');
        return;
      }
      const cleanCode = nativeSmsCode.trim();
      if (!cleanCode) {
        setNativeLoginError('请输入收到的短信验证码');
        return;
      }
      setNativeSubmitting(true);
      try {
        const res = await api.verifyPhoneLogin(phoneLoginId, cleanCode);
        if (!res.data.done && res.data.challenge?.kind === 'two_step') {
          enterSecondVerifyStep(
            res.data.login_id || phoneLoginId,
            res.data.challenge,
            res.message,
          );
          return;
        }
        completeLoginSuccess(res.data.nickname, res.data.web_ready, res.message);
      } catch (err: any) {
        setNativeLoginError(err.message || '短信验证码登录失败');
      } finally {
        setNativeSubmitting(false);
      }
      return;
    }

    if (!nativePassword.trim()) {
      setNativeLoginError('请输入抖音登录密码');
      return;
    }
    setNativeSubmitting(true);
    try {
      const res = await api.passwordLogin({
        account_id: loginTarget?.accountId,
        alias: alias.trim() || loginTarget?.alias || undefined,
        mobile: cleanMobile,
        password: nativePassword,
      });
      if (!res.data.done && res.data.challenge?.kind === 'two_step' && res.data.login_id) {
        enterSecondVerifyStep(res.data.login_id, res.data.challenge, res.message);
        return;
      }
      completeLoginSuccess(res.data.nickname, res.data.web_ready, res.message);
    } catch (err: any) {
      setNativeLoginError(err.message || '手机号密码登录失败');
    } finally {
      setNativeSubmitting(false);
    }
  };

  const handleSubmitSecondVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!phoneLoginId || !selectedVerifyWay) return;
    setNativeLoginError('');
    setNativeSubmitting(true);
    try {
      const res = await api.submitAccountLoginVerification(phoneLoginId, {
        way: selectedVerifyWay,
        code: isDownSmsVerifyWay(selectedVerifyWay) ? secondVerifyCode.trim() : undefined,
        password: selectedVerifyWay === 'pwd_verify' ? secondVerifyPassword : undefined,
      });
      if (res.data.done) {
        completeLoginSuccess(res.data.nickname, res.data.web_ready, res.message);
        return;
      }
      if (res.message) {
        setSecondVerifyHint(res.message);
      }
    } catch (err: any) {
      setNativeLoginError(err.message || '安全身份验证未通过');
    } finally {
      setNativeSubmitting(false);
    }
  };

  const downloadNativeImportTemplate = () => {
    const template = {
      account_id: nativeImportAccount?.id || '',
      alias: nativeImportAccount?.alias || alias.trim() || '账号备注',
      device: {
        device_id: '官方 Android 客户端 device_id',
        install_id: '官方 Android 客户端 install_id',
        openudid: '官方 Android 客户端 openudid',
        cdid: '官方 Android 客户端 cdid',
        aid: '1128',
        app_name: 'aweme',
        app_version: '40.8.0',
        version_code: '400801',
        device_platform: 'android',
        channel: 'update',
        package: 'com.ss.android.ugc.aweme',
        user_agent: '与提取 Cookie 的官方 Android 客户端完全一致',
      },
      cookie: '完整 Cookie；包含 sessionid、sid_tt、sid_guard、d_ticket',
      uid: '可留空，已有账号会自动补齐',
      sec_uid: '可留空，已有账号会自动补齐',
      nickname: '可留空，已有账号会自动补齐',
      avatar_url: '可留空，已有账号会自动补齐',
      mobile: '',
      session_key: null,
      d_ticket: null,
      x_tt_token: '官方 App 的 X-Tt-Token',
      token_encrypted: null,
      ts_sign: null,
      attest_ts_sign: null,
      mfa_token: null,
      logged_in_at: 0,
      last_verified_at: null,
      last_beat_at: null,
    };
    const blob = new Blob([JSON.stringify(template, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = 'sparklight-native-session-template.json';
    anchor.click();
    URL.revokeObjectURL(url);
  };

  const handleNativeImport = async (e: React.FormEvent) => {
    e.preventDefault();
    setNativeImportError('');
    let parsed: unknown;
    try {
      parsed = JSON.parse(nativeImportText);
    } catch {
      setNativeImportError('文件不是合法 JSON');
      return;
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      setNativeImportError('导入文件必须是 JSON 对象');
      return;
    }
    setIsNativeImporting(true);
    try {
      const payload = {
        ...(parsed as Record<string, unknown>),
        account_id: nativeImportAccount?.id || '',
        alias: nativeImportAccount?.alias || alias.trim() || undefined,
      };
      const result = await api.importNativeSession(payload);
      setIsNativeImportOpen(false);
      setNativeImportAccount(null);
      setNativeImportText('');
      setNativeImportFileName('');
      loadAccounts();
      onRefresh();
      if (result.warning || result.data.web_ready === false) {
        toast.info(result.warning || 'App 原生登录已保存，Web/IM 发送材料待后台恢复');
      } else {
        toast.success(result.message || '官方原生会话已导入');
      }
    } catch (error: any) {
      setNativeImportError(error.message || '导入失败');
    } finally {
      setIsNativeImporting(false);
    }
  };

  const openNativeImport = (account: AccountDto | null) => {
    setNativeImportError('');
    setNativeImportText('');
    setNativeImportFileName('');
    setNativeImportAccount(account);
    setIsNativeImportOpen(true);
  };
  const handleEdit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editAccount) return;
    setIsSubmitting(true);
    setFormError('');
    try {
      await api.updateAccount(editAccount.id, {
        alias: alias.trim() || undefined,
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

  const handleCheckSession = async (id: string) => {
    setCheckingIds((prev) => new Set(prev).add(id));
    try {
      const res = await api.checkAccount(id);
      if (res.data?.is_valid) {
        toast.success(res.message);
      } else if (res.data?.confirmed === false) {
        toast.info(res.message);
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
    <div className="space-y-4">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
            抖音账号管理
          </h1>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            多账号指纹隔离运行，App 原生会话加密保存并由官方 TokenBeat 维护
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => {
              openNativeLoginModal();
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
            支持抖音 App 原生手机号验证码、密码直连登录，或导入官方原生会话。
          </p>
          <button
            onClick={() => openNativeLoginModal()}
            className="mt-4 px-4 py-2 text-xs font-medium rounded-xl bg-orange-500 hover:bg-orange-600 text-white"
          >
            立即添加第一个账号
          </button>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 2xl:grid-cols-3 gap-4">
          {accounts.map((acc) => {
            const nativeReady = acc.status === 'ACTIVE' && acc.native_ready;
            const nativeMissing = acc.status === 'ACTIVE' && !acc.native_ready;
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
                              nativeReady
                                ? 'bg-emerald-100 dark:bg-emerald-950/40 text-emerald-600 dark:text-emerald-400'
                                : nativeMissing
                                  ? 'bg-amber-100 dark:bg-amber-950/40 text-amber-700 dark:text-amber-400'
                                  : 'bg-rose-100 dark:bg-rose-950/40 text-rose-600 dark:text-rose-400'
                            }`}
                          >
                            {nativeReady ? <CheckCircle2 className="w-3 h-3" /> : <AlertTriangle className="w-3 h-3" />}
                            {nativeReady
                              ? 'App 登录正常'
                              : nativeMissing
                                ? '原生会话待补'
                                : acc.status === 'DISABLED'
                                  ? '已停用'
                                  : '已失效'}
                          </span>
                        </div>
                        {nativeReady && acc.im_history_status && acc.im_history_status !== 'AVAILABLE' && (
                          <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-1 leading-snug break-words">
                            {acc.im_history_status === 'INVALID' ? '消息会话待校验，执行时重新获取' : '消息会话待刷新，执行时自动获取'}
                          </p>
                        )}
                        {nativeMissing && (
                          <p className="mt-1 text-[11px] leading-snug text-amber-600 dark:text-amber-400">
                            完成 App 原生登录或导入官方会话后才能执行
                          </p>
                        )}
                        {!acc.nickname && (
                          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">未同步昵称</p>
                        )}
                      </div>
                    </div>

                    <div className="flex items-center gap-1 shrink-0">
                      {/* 重新登录并同步 App 原生会话 */}
                      <button
                        onClick={() => openNativeLoginModal({ accountId: acc.id, alias: acc.alias })}
                        className="p-1.5 text-orange-500 hover:text-orange-600 rounded-lg hover:bg-orange-50 dark:hover:bg-orange-950/30 transition"
                        title="使用抖音 App 原生方式重新登录该账号"
                      >
                        <LogIn className="w-3.5 h-3.5" />
                      </button>
                      <button
                        onClick={() => {
                          openNativeImport(acc);
                        }}
                        className="p-1.5 text-slate-400 hover:text-orange-600 rounded-lg hover:bg-orange-50 dark:hover:bg-orange-950/30 transition"
                        title="导入该账号的官方 Android 原生会话"
                      >
                        <Upload className="w-3.5 h-3.5" />
                      </button>
                      <button
                        onClick={() => {
                          setEditAccount(acc);
                          setAlias(acc.alias);
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
                      <span className="text-slate-400 text-[11px]">登录会话:</span>
                      <span className={`text-[11px] font-medium ${acc.native_ready ? 'text-emerald-600 dark:text-emerald-400' : 'text-amber-600 dark:text-amber-400'}`}>
                    {acc.native_ready ? 'App 原生会话已保存' : '未导入可用原生会话'}
                      </span>
                    </div>
                {acc.native_sid_expires_at && (
                  <div className="flex justify-between items-center">
                    <span className="text-slate-400 text-[11px]">原生会话到期:</span>
                    <span className="text-[11px] font-mono">
                      {formatBeijingDateTime(acc.native_sid_expires_at * 1000)}
                    </span>
                  </div>
                )}
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
                      <span className="text-[11px] text-slate-400 font-mono">
                        {acc.last_checked_at ? formatBeijingDateTime(acc.last_checked_at) : '未检测'}
                      </span>
                    </div>
                  </div>
                </div>

                <div className="mt-4 pt-3 border-t border-slate-100 dark:border-slate-800/80 flex flex-wrap sm:flex-nowrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2 flex-wrap sm:flex-nowrap shrink-0">
                    <button
                      onClick={() => handleCheckSession(acc.id)}
                      disabled={isChecking}
                      className="flex items-center gap-1 px-2.5 py-1.5 text-xs font-medium rounded-lg border border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition"
                    >
                      <RefreshCw className={`w-3 h-3 ${isChecking ? 'animate-spin' : ''}`} />
                      <span>检测登录态</span>
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
                    disabled={isRunning || !nativeReady}
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

      {/* App 原生登录弹窗（新增账号 / 重新登录） */}
      {isAddModalOpen && (
        <ModalPortal>
          <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/60 backdrop-blur-sm p-4 overflow-y-auto">
          <div className="relative w-full max-w-lg rounded-2xl bg-white dark:bg-slate-900 p-6 shadow-2xl border border-slate-200 dark:border-slate-800 animate-in fade-in zoom-in-95 duration-150">
            <button
              onClick={() => {
                if (phoneLoginId) {
                  void api.cancelAccountLogin(phoneLoginId).catch(() => {});
                }
                resetSecondVerifyState();
                setIsAddModalOpen(false);
                setLoginTarget(null);
              }}
              className="absolute right-4 top-4 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200"
            >
              <X className="w-5 h-5" />
            </button>

            <h3 className="text-base font-bold text-slate-900 dark:text-slate-100 mb-1">
              {secondVerifyChallenge
                ? '抖音安全身份验证'
                : loginTarget?.accountId
                  ? `重新登录账号：${loginTarget.alias || '抖音账号'}`
                  : '抖音账号登录'}
            </h3>
            <p className="text-xs text-slate-500 dark:text-slate-400 mb-4">
              {secondVerifyChallenge
                ? secondVerifyHint || secondVerifyChallenge.scene_description || '首次在当前服务器登录该账号，请任选一种方式完成本人核验'
                : '内置官方安全签名与设备隔离上下文，登录后自动维护长期会话'}
            </p>

            {secondVerifyChallenge ? (
              <form onSubmit={handleSubmitSecondVerify} className="space-y-4">
                <div className="flex flex-wrap gap-1.5">
                  {secondVerifyChallenge.ways
                    .filter((w) => w.supported)
                    .map((way) => {
                      const activeWay = selectedVerifyWay === way.kind;
                      return (
                        <button
                          key={way.kind}
                          type="button"
                          onClick={() => {
                            setSelectedVerifyWay(way.kind);
                            setNativeLoginError('');
                            setSecondVerifyDelivery(null);
                            setSecondVerifyPolling(false);
                            if (way.description) setSecondVerifyHint(way.description);
                            if (isUpSmsVerifyWay(way.kind) || isQrVerifyWay(way.kind)) {
                              void handlePrepareSecondVerify(phoneLoginId, way.kind, true);
                            }
                          }}
                          className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition ${
                            activeWay
                              ? 'border-orange-500 bg-orange-50 text-orange-700 dark:bg-orange-950/40 dark:text-orange-300 dark:border-orange-500/70'
                              : 'border-slate-200 bg-slate-50 text-slate-600 hover:bg-slate-100 dark:border-slate-800 dark:bg-slate-800/60 dark:text-slate-300'
                          }`}
                        >
                          {way.label}
                        </button>
                      );
                    })}
                </div>

                {isUpSmsVerifyWay(selectedVerifyWay) && (
                  <div className="space-y-3 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-800/40 p-3.5">
                    {secondVerifyPreparing ? (
                      <div className="flex items-center gap-2 text-xs text-slate-500 py-3 justify-center">
                        <Loader2 className="w-4 h-4 animate-spin text-orange-500" />
                        <span>正在获取官方短信核验指令…</span>
                      </div>
                    ) : secondVerifyDelivery?.sms_content && secondVerifyDelivery?.channel_mobile ? (
                      <>
                        <p className="text-xs text-slate-600 dark:text-slate-300">
                          请使用绑定手机号{' '}
                          <span className="font-semibold text-slate-900 dark:text-slate-100">
                            {secondVerifyChallenge.masked_mobile || phoneMobileMasked || nativeMobile}
                          </span>{' '}
                          编辑以下短信发送至指定号码：
                        </p>
                        <div className="space-y-2">
                          <div className="flex items-center justify-between gap-2 rounded-lg bg-white dark:bg-slate-900 px-3 py-2 border border-slate-200 dark:border-slate-700">
                            <div className="min-w-0">
                              <div className="text-[11px] text-slate-400">短信内容</div>
                              <div className="font-mono text-xs font-semibold text-slate-900 dark:text-slate-100 break-all">
                                {secondVerifyDelivery.sms_content}
                              </div>
                            </div>
                            <button
                              type="button"
                              onClick={async () => {
                                if (await copyToClipboard(secondVerifyDelivery.sms_content || '')) {
                                  toast.success('短信内容已复制');
                                }
                              }}
                              className="p-1.5 rounded-lg text-slate-500 hover:text-orange-600 hover:bg-slate-100 dark:hover:bg-slate-800"
                              title="复制短信内容"
                            >
                              <Copy className="w-3.5 h-3.5" />
                            </button>
                          </div>
                          <div className="flex items-center justify-between gap-2 rounded-lg bg-white dark:bg-slate-900 px-3 py-2 border border-slate-200 dark:border-slate-700">
                            <div className="min-w-0">
                              <div className="text-[11px] text-slate-400">接收号码</div>
                              <div className="font-mono text-xs font-semibold text-slate-900 dark:text-slate-100 break-all">
                                {secondVerifyDelivery.channel_mobile}
                              </div>
                            </div>
                            <button
                              type="button"
                              onClick={async () => {
                                if (await copyToClipboard(secondVerifyDelivery.channel_mobile || '')) {
                                  toast.success('接收号码已复制');
                                }
                              }}
                              className="p-1.5 rounded-lg text-slate-500 hover:text-orange-600 hover:bg-slate-100 dark:hover:bg-slate-800"
                              title="复制接收号码"
                            >
                              <Copy className="w-3.5 h-3.5" />
                            </button>
                          </div>
                        </div>
                      </>
                    ) : (
                      <button
                        type="button"
                        onClick={() => void handlePrepareSecondVerify(phoneLoginId, selectedVerifyWay)}
                        className="w-full py-2 text-xs font-medium rounded-lg border border-orange-200 bg-orange-50 text-orange-700 hover:bg-orange-100 dark:border-orange-900/60 dark:bg-orange-950/30 dark:text-orange-300"
                      >
                        获取短信编辑内容与接收号码
                      </button>
                    )}
                  </div>
                )}

                {selectedVerifyWay === 'pwd_verify' && (
                  <div>
                    <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                      抖音登录密码
                    </label>
                    <input
                      type="password"
                      autoComplete="current-password"
                      value={secondVerifyPassword}
                      onChange={(e) => {
                        setSecondVerifyPassword(e.target.value);
                        setNativeLoginError('');
                      }}
                      placeholder="输入该账号的抖音登录密码完成身份核验"
                      className="w-full px-3 py-2 text-xs rounded-xl border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 focus:ring-2 focus:ring-orange-500 focus:outline-none"
                    />
                  </div>
                )}

                {isDownSmsVerifyWay(selectedVerifyWay) && (
                  <div>
                    <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                      二次安全验证码
                    </label>
                    <div className="flex gap-2">
                      <input
                        type="text"
                        inputMode="numeric"
                        value={secondVerifyCode}
                        onChange={(e) => {
                          setSecondVerifyCode(e.target.value.replace(/\D/g, '').slice(0, 8));
                          setNativeLoginError('');
                        }}
                        placeholder="输入 4~6 位安全验证码"
                        className="min-w-0 flex-1 px-3 py-2 text-xs rounded-xl border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 focus:ring-2 focus:ring-orange-500 focus:outline-none"
                      />
                      <button
                        type="button"
                        disabled={secondVerifyPreparing || secondVerifyCooldown > 0}
                        onClick={() => void handlePrepareSecondVerify(phoneLoginId, selectedVerifyWay)}
                        className="shrink-0 px-3.5 py-2 text-xs font-medium rounded-xl border border-orange-200 bg-orange-50 text-orange-700 hover:bg-orange-100 disabled:opacity-50 dark:border-orange-900/60 dark:bg-orange-950/30 dark:text-orange-300"
                      >
                        {secondVerifyPreparing
                          ? '发送中…'
                          : secondVerifyCooldown > 0
                            ? `${secondVerifyCooldown}s 后重发`
                            : selectedVerifyWay.includes('voice')
                              ? '拨打语音码'
                              : '发送验证码'}
                      </button>
                    </div>
                  </div>
                )}

                {isPushVerifyWay(selectedVerifyWay) && (
                  <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-800/40 p-4 text-center space-y-2.5">
                    <Smartphone className="w-7 h-7 text-orange-500 mx-auto" />
                    <p className="text-xs text-slate-600 dark:text-slate-300">
                      {secondVerifyPolling
                        ? '已发送通知至手机抖音 App，请在手机端点击「允许登录」，页面会自动完成登录…'
                        : '点击下方按钮向已登录该账号的手机抖音 App 发送一键确认通知'}
                    </p>
                    <button
                      type="button"
                      disabled={secondVerifyPreparing}
                      onClick={() => void handlePrepareSecondVerify(phoneLoginId, selectedVerifyWay)}
                      className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-medium rounded-xl bg-orange-500 hover:bg-orange-600 text-white disabled:opacity-50"
                    >
                      {secondVerifyPreparing ? (
                        <Loader2 className="w-3.5 h-3.5 animate-spin" />
                      ) : (
                        <Smartphone className="w-3.5 h-3.5" />
                      )}
                      <span>{secondVerifyPolling ? '重新发送确认通知' : '发送手机抖音确认通知'}</span>
                    </button>
                  </div>
                )}

                {isQrVerifyWay(selectedVerifyWay) && (
                  <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50/70 dark:bg-slate-800/40 p-4 flex flex-col items-center space-y-3">
                    {secondVerifyPreparing ? (
                      <div className="flex items-center gap-2 text-xs text-slate-500 py-8">
                        <Loader2 className="w-4 h-4 animate-spin text-orange-500" />
                        <span>正在生成安全核验二维码…</span>
                      </div>
                    ) : secondVerifyDelivery?.qrcode ? (
                      <>
                        <img
                          src={secondVerifyDelivery.qrcode}
                          alt="安全身份核验二维码"
                          className="w-40 h-40 rounded-xl border border-slate-200 bg-white p-2 object-contain"
                        />
                        <p className="text-xs text-slate-600 dark:text-slate-300 text-center">
                          打开手机抖音 App「扫一扫」完成核验，核验通过后自动登录
                        </p>
                        <button
                          type="button"
                          onClick={() => void handlePrepareSecondVerify(phoneLoginId, selectedVerifyWay)}
                          className="text-[11px] font-medium text-orange-600 hover:text-orange-700 dark:text-orange-400"
                        >
                          刷新二维码
                        </button>
                      </>
                    ) : (
                      <button
                        type="button"
                        onClick={() => void handlePrepareSecondVerify(phoneLoginId, selectedVerifyWay)}
                        className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-medium rounded-xl bg-orange-500 hover:bg-orange-600 text-white"
                      >
                        <QrCode className="w-3.5 h-3.5" />
                        <span>生成安全核验二维码</span>
                      </button>
                    )}
                  </div>
                )}

                {nativeLoginError && (
                  <div className="rounded-xl border border-rose-200 bg-rose-50/80 px-3 py-2 text-xs text-rose-600 dark:border-rose-900/50 dark:bg-rose-950/30 dark:text-rose-300">
                    {nativeLoginError}
                  </div>
                )}

                <div className="flex gap-2.5 pt-2">
                  <button
                    type="button"
                    onClick={() => {
                      resetSecondVerifyState();
                      setNativeLoginError('');
                    }}
                    className="flex items-center justify-center gap-1 px-4 py-2 text-xs font-medium rounded-xl border border-slate-200 dark:border-slate-800 hover:bg-slate-100 dark:hover:bg-slate-800"
                  >
                    <ArrowLeft className="w-3.5 h-3.5" />
                    <span>返回</span>
                  </button>
                  <button
                    type="submit"
                    disabled={nativeSubmitting}
                    className="flex-1 flex items-center justify-center gap-1.5 px-4 py-2 text-xs font-medium rounded-xl bg-orange-500 hover:bg-orange-600 text-white disabled:opacity-50"
                  >
                    {nativeSubmitting ? (
                      <Loader2 className="w-3.5 h-3.5 animate-spin" />
                    ) : (
                      <ShieldCheck className="w-3.5 h-3.5" />
                    )}
                    <span>
                      {nativeSubmitting
                        ? '正在核验…'
                        : isUpSmsVerifyWay(selectedVerifyWay)
                          ? '我已发送短信，完成登录'
                          : isPushVerifyWay(selectedVerifyWay) || isQrVerifyWay(selectedVerifyWay)
                            ? '我已在手机确认，立即检测'
                            : '完成核验并登录'}
                    </span>
                  </button>
                </div>
              </form>
            ) : (
            <form onSubmit={handleCreate} className="space-y-4">
              <div className="grid grid-cols-2 gap-1.5 rounded-xl bg-slate-100 p-1 dark:bg-slate-800/80">
                <button
                  type="button"
                  onClick={() => {
                    setNativeLoginMode('sms');
                    setNativeLoginError('');
                  }}
                  className={`flex items-center justify-center gap-1.5 rounded-lg py-2 text-xs font-medium transition ${
                    nativeLoginMode === 'sms'
                      ? 'bg-white text-orange-600 shadow-sm dark:bg-slate-900 dark:text-orange-400'
                      : 'text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-200'
                  }`}
                >
                  <MessageSquareText className="h-3.5 w-3.5" />
                  <span>短信验证码登录</span>
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setNativeLoginMode('password');
                    setNativeLoginError('');
                  }}
                  className={`flex items-center justify-center gap-1.5 rounded-lg py-2 text-xs font-medium transition ${
                    nativeLoginMode === 'password'
                      ? 'bg-white text-orange-600 shadow-sm dark:bg-slate-900 dark:text-orange-400'
                      : 'text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-200'
                  }`}
                >
                  <KeyRound className="h-3.5 w-3.5" />
                  <span>手机号密码登录</span>
                </button>
              </div>

              {!loginTarget?.accountId && (
                <div>
                  <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                    账号备注（可选，留空自动使用抖音昵称）
                  </label>
                  <input
                    type="text"
                    value={alias}
                    onChange={(e) => setAlias(e.target.value)}
                    placeholder="留空则自动读取抖音账号真实昵称"
                    className="w-full px-3 py-2 text-xs rounded-xl border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 focus:ring-2 focus:ring-orange-500 focus:outline-none"
                  />
                </div>
              )}

              <div>
                <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                  中国大陆手机号（+86）
                </label>
                <input
                  type="tel"
                  inputMode="numeric"
                  autoComplete="tel"
                  value={nativeMobile}
                  onChange={(e) => {
                    setNativeMobile(e.target.value.replace(/[^\d+ -]/g, '').slice(0, 16));
                    setNativeLoginError('');
                  }}
                  placeholder="请输入 11 位手机号"
                  className="w-full px-3 py-2 text-xs rounded-xl border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 focus:ring-2 focus:ring-orange-500 focus:outline-none"
                />
              </div>

              {nativeLoginMode === 'sms' ? (
                <div>
                  <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                    短信验证码
                  </label>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      inputMode="numeric"
                      autoComplete="one-time-code"
                      value={nativeSmsCode}
                      onChange={(e) => {
                        setNativeSmsCode(e.target.value.replace(/\D/g, '').slice(0, 8));
                        setNativeLoginError('');
                      }}
                      placeholder="输入 4~6 位短信验证码"
                      className="min-w-0 flex-1 px-3 py-2 text-xs rounded-xl border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 focus:ring-2 focus:ring-orange-500 focus:outline-none"
                    />
                    <button
                      type="button"
                      disabled={smsSending || smsCooldown > 0 || !nativeMobile.trim()}
                      onClick={() => void handleSendPhoneCode()}
                      className="shrink-0 px-3.5 py-2 text-xs font-medium rounded-xl border border-orange-200 bg-orange-50 text-orange-700 hover:bg-orange-100 disabled:opacity-50 dark:border-orange-900/60 dark:bg-orange-950/30 dark:text-orange-300"
                    >
                      {smsSending ? (
                        <span className="flex items-center gap-1">
                          <Loader2 className="h-3.5 w-3.5 animate-spin" />
                          发送中
                        </span>
                      ) : smsCooldown > 0 ? (
                        `${smsCooldown}s 后重发`
                      ) : (
                        '获取验证码'
                      )}
                    </button>
                  </div>
                  {phoneMobileMasked && (
                    <p className="mt-1.5 text-[11px] text-emerald-600 dark:text-emerald-400">
                      验证码已发送至 {phoneMobileMasked}，请在有效期内输入
                    </p>
                  )}
                </div>
              ) : (
                <div>
                  <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                    抖音登录密码
                  </label>
                  <input
                    type="password"
                    autoComplete="current-password"
                    value={nativePassword}
                    onChange={(e) => {
                      setNativePassword(e.target.value);
                      setNativeLoginError('');
                    }}
                    placeholder="请输入抖音账号密码（仅用于本次 mix_mode 加密认证，不落盘）"
                    className="w-full px-3 py-2 text-xs rounded-xl border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 focus:ring-2 focus:ring-orange-500 focus:outline-none"
                  />
                </div>
              )}

              <div className="flex items-center justify-between rounded-xl bg-slate-50 px-3 py-2 dark:bg-slate-800/50 border border-slate-200/70 dark:border-slate-800">
                <span className="text-[11px] text-slate-500 dark:text-slate-400">
                  已有抓包提取的官方客户端会话？
                </span>
                <button
                  type="button"
                  onClick={() => {
                    const targetAcc = loginTarget?.accountId
                      ? accounts.find((a) => a.id === loginTarget.accountId) || null
                      : null;
                    setIsAddModalOpen(false);
                    setLoginTarget(null);
                    openNativeImport(targetAcc);
                  }}
                  className="flex items-center gap-1 text-[11px] font-medium text-orange-600 hover:text-orange-700 dark:text-orange-400"
                >
                  <Upload className="h-3 w-3" />
                  <span>导入原生会话 JSON</span>
                </button>
              </div>

              {nativeLoginError && (
                <div className="rounded-xl border border-rose-200 bg-rose-50/80 px-3 py-2 text-xs text-rose-600 dark:border-rose-900/50 dark:bg-rose-950/30 dark:text-rose-300">
                  {nativeLoginError}
                </div>
              )}

              <div className="flex gap-2.5 pt-2">
                <button
                  type="button"
                  onClick={() => {
                    setIsAddModalOpen(false);
                    setLoginTarget(null);
                  }}
                  className="flex-1 px-4 py-2 text-xs font-medium rounded-xl border border-slate-200 dark:border-slate-800 hover:bg-slate-100 dark:hover:bg-slate-800"
                >
                  取消
                </button>
                <button
                  type="submit"
                  disabled={nativeSubmitting}
                  className="flex-1 flex items-center justify-center gap-1.5 px-4 py-2 text-xs font-medium rounded-xl bg-orange-500 hover:bg-orange-600 text-white disabled:opacity-50"
                >
                  {nativeSubmitting ? (
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  ) : (
                    <LogIn className="w-3.5 h-3.5" />
                  )}
                  <span>{nativeSubmitting ? '正在登录…' : '立即登录'}</span>
                </button>
              </div>
            </form>
            )}
          </div>
          </div>
        </ModalPortal>
      )}

      {/* Native Session Import Modal */}
      {isNativeImportOpen && (
        <ModalPortal>
          <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/60 backdrop-blur-sm p-4 overflow-y-auto">
          <div className="relative w-full max-w-lg rounded-2xl bg-white dark:bg-slate-900 p-6 shadow-2xl border border-slate-200 dark:border-slate-800 animate-in fade-in zoom-in-95 duration-150">
            <button
              onClick={() => setIsNativeImportOpen(false)}
              className="absolute right-4 top-4 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200"
            >
              <X className="w-5 h-5" />
            </button>
            <div className="flex items-center gap-2.5 mb-1">
              <div className="p-2 rounded-xl bg-orange-500/10 text-orange-500">
                <Upload className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-base font-bold text-slate-900 dark:text-slate-100">导入官方原生会话</h3>
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  {nativeImportAccount
                    ? `仅导入到当前账号：${accountDisplayName(nativeImportAccount.nickname, nativeImportAccount.alias)}`
                    : '新增账号并绑定同一官方 Android 客户端会话'}
                </p>
              </div>
            </div>

            <form onSubmit={handleNativeImport} className="mt-4 space-y-4">
              {nativeImportAccount && (
                <div className="flex items-start gap-2.5 rounded-xl border border-orange-200 bg-orange-50/70 p-3 dark:border-orange-900/60 dark:bg-orange-950/20">
                  <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-orange-500" />
                  <div className="min-w-0 text-xs leading-relaxed text-slate-700 dark:text-slate-300">
                    <p className="font-medium">导入目标已绑定，无需在文件中填写 account_id</p>
                    <p className="mt-1 text-[11px] text-slate-500 dark:text-slate-400">
                      UID 与 sec_uid 必须和该账号一致；文件只用于本次导入，不会回传或展示 Cookie。
                    </p>
                  </div>
                </div>
              )}
              {!nativeImportAccount && (
                <div className="flex items-start gap-2.5 rounded-xl border border-slate-200 bg-slate-50/70 p-3 dark:border-slate-800 dark:bg-slate-800/40">
                  <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-orange-500" />
                  <p className="text-[11px] leading-relaxed text-slate-600 dark:text-slate-400">
                    将自动创建账号，并在保存前按抖音 UID 查重；文件中的 account_id 可留空。
                  </p>
                </div>
              )}
              <div className="flex gap-2">
                <label className="flex flex-1 cursor-pointer items-center justify-center gap-1.5 rounded-xl border border-slate-200 px-3 py-2 text-xs font-medium text-slate-700 hover:bg-slate-50 dark:border-slate-800 dark:text-slate-300 dark:hover:bg-slate-800">
                  <Upload className="w-3.5 h-3.5" />
                  <span>{nativeImportFileName || '选择 JSON 文件'}</span>
                  <input
                    type="file"
                    accept="application/json,.json"
                    className="hidden"
                    onChange={async (event) => {
                      const file = event.target.files?.[0];
                      event.target.value = '';
                      if (!file) return;
                      if (file.size > 256 * 1024) {
                        setNativeImportError('文件超过 256 KiB 安全上限');
                        return;
                      }
                      try {
                        const text = await file.text();
                        setNativeImportText(text);
                        setNativeImportFileName(file.name);
                        setNativeImportError('');
                      } catch {
                        setNativeImportError('读取文件失败');
                      }
                    }}
                  />
                </label>
                <button
                  type="button"
                  onClick={downloadNativeImportTemplate}
                  className="flex items-center justify-center gap-1.5 rounded-xl border border-slate-200 px-3 py-2 text-xs font-medium text-slate-700 hover:bg-slate-50 dark:border-slate-800 dark:text-slate-300 dark:hover:bg-slate-800"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>模板</span>
                </button>
              </div>

              {nativeImportError && <p className="text-xs text-rose-500">{nativeImportError}</p>}

              <div className="flex gap-2.5 pt-1">
                <button
                  type="button"
                  onClick={() => setIsNativeImportOpen(false)}
                  className="flex-1 px-4 py-2 text-xs font-medium rounded-xl border border-slate-200 dark:border-slate-800 hover:bg-slate-100 dark:hover:bg-slate-800"
                >
                  取消
                </button>
                <button
                  type="submit"
                  disabled={isNativeImporting || !nativeImportText.trim()}
                  className="flex-1 flex items-center justify-center gap-1.5 px-4 py-2 text-xs font-medium rounded-xl bg-orange-500 hover:bg-orange-600 text-white disabled:opacity-50"
                >
                  {isNativeImporting ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Upload className="w-3.5 h-3.5" />}
                  <span>导入并加密保存</span>
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
              可修改别名或账号级 Bark 推送 Key
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
