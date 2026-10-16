import React, { useEffect, useState } from 'react';
import {
  Bell,
  Clock,
  KeyRound,
  ShieldCheck,
  Send,
  Loader2,
  Check,
  Eye,
  EyeOff,
  Copy,
  RotateCcw,
} from 'lucide-react';
import { api, getStoredApiKey, setStoredApiKey } from '../api/client';
import { SystemSettings } from '../types';
import { useToast } from '../components/ui/Toast';
import { copyToClipboard } from '../utils/clipboard';

interface Props {
  onApiKeyUpdated: () => void;
}

export const SettingsPage: React.FC<Props> = ({ onApiKeyUpdated }) => {
  const toast = useToast();
  const [settings, setSettings] = useState<SystemSettings | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  // Form states
  const [localApiKey, setLocalApiKey] = useState(getStoredApiKey());
  const [showLocalApiKey, setShowLocalApiKey] = useState(false);
  const [barkServer, setBarkServer] = useState('https://api.day.app');
  const [barkKey, setBarkKey] = useState('');
  const [showBarkKey, setShowBarkKey] = useState(false);
  const [sparkTime, setSparkTime] = useState('09:30');
  const [minDelay, setMinDelay] = useState(5);
  const [maxDelay, setMaxDelay] = useState(15);
  const [maxRetries, setMaxRetries] = useState(3);

  const [isSaving, setIsSaving] = useState(false);
  const [isTestingBark, setIsTestingBark] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);
  const [copySuccess, setCopySuccess] = useState(false);

  const loadSettings = async () => {
    try {
      const data = await api.getSettings();
      setSettings(data);
      setBarkServer(data.bark_server);
      setBarkKey(data.bark_key || '');
      setSparkTime(data.spark_time);
      setMinDelay(data.min_delay_secs);
      setMaxDelay(data.max_delay_secs);
      setMaxRetries(data.max_retries ?? 3);
    } catch (e) {
      console.error(e);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadSettings();
  }, []);

  const handleSaveLocalApiKey = (e: React.FormEvent) => {
    e.preventDefault();
    setStoredApiKey(localApiKey.trim());
    onApiKeyUpdated();
    toast.success('本地 API Key 已更新');
  };

  const handleCopyLocalApiKey = async () => {
    if (!localApiKey) return;
    const ok = await copyToClipboard(localApiKey);
    if (ok) {
      setCopySuccess(true);
      toast.success('API Key 已成功复制到剪贴板');
      setTimeout(() => setCopySuccess(false), 2000);
    } else {
      toast.error('复制失败，请手动在输入框中复制');
    }
  };

  const handleSaveSettings = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSaving(true);
    setSaveSuccess(false);
    try {
      await api.updateSettings({
        bark_server: barkServer.trim(),
        bark_key: barkKey.trim() || undefined,
        spark_time: sparkTime.trim(),
        min_delay_secs: Number(minDelay),
        max_delay_secs: Number(maxDelay),
        max_retries: Number(maxRetries),
      });
      setSaveSuccess(true);
      toast.success('系统配置已成功保存');
      setTimeout(() => setSaveSuccess(false), 3000);
      loadSettings();
    } catch (e: any) {
      toast.error(`保存失败: ${e.message}`);
    } finally {
      setIsSaving(false);
    }
  };

  const handleTestBark = async () => {
    if (!barkKey.trim()) {
      toast.info('请先填入 Bark Device Key 再测试');
      return;
    }
    setIsTestingBark(true);
    try {
      const res = await api.testBark(barkServer.trim(), barkKey.trim());
      toast.success(res.message);
    } catch (e: any) {
      toast.error(`测试推送失败: ${e.message}`);
    } finally {
      setIsTestingBark(false);
    }
  };

  if (isLoading) {
    return (
      <div className="space-y-6 max-w-4xl" aria-busy="true">
        <div>
          <h1 className="text-xl font-bold text-slate-900 dark:text-slate-100">系统配置</h1>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">管理 Bark 实时推送告警、每日续火花执行计划、失败重试次数及安全认证</p>
        </div>
        <div className="flex justify-center py-16" role="status" aria-label="加载设置">
          <Loader2 className="w-8 h-8 text-orange-500 animate-spin" />
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-4xl">
      <div>
        <h1 className="text-xl font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
          系统配置
        </h1>
        <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
          管理 Bark 实时推送告警、每日续火花执行计划、失败重试次数及安全认证
        </p>
      </div>

      {/* API Key Card - Sensitive Handling */}
      <div className="rounded-2xl bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800/80 p-5 shadow-sm space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-xl bg-orange-100 dark:bg-orange-950/40 text-orange-600 dark:text-orange-400">
              <KeyRound className="w-4 h-4" />
            </div>
            <div>
              <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">API Key 敏感认证信息</h2>
              <p className="text-xs text-slate-500 dark:text-slate-400">用于校验接口请求权限，请妥善保管勿公开泄露</p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={handleCopyLocalApiKey}
              className="flex items-center gap-1 px-2.5 py-1 text-xs font-medium rounded-lg border border-slate-200 dark:border-slate-800 text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition"
              title="复制 API Key"
            >
              {copySuccess ? <Check className="w-3.5 h-3.5 text-emerald-500" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copySuccess ? '已复制' : '复制Key'}</span>
            </button>
          </div>
        </div>

        <form onSubmit={handleSaveLocalApiKey} className="space-y-2">
          <div className="relative">
            <input
              type={showLocalApiKey ? 'text' : 'password'}
              value={localApiKey}
              onChange={(e) => setLocalApiKey(e.target.value)}
              placeholder="sk_..."
              className="w-full pl-3 pr-10 py-2.5 text-xs font-mono rounded-xl border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 focus:ring-2 focus:ring-orange-500 focus:outline-none"
            />
            <button
              type="button"
              onClick={() => setShowLocalApiKey(!showLocalApiKey)}
              className="absolute inset-y-0 right-0 pr-3 flex items-center text-slate-400 hover:text-slate-600 dark:hover:text-slate-200"
              title={showLocalApiKey ? '隐藏明文' : '查看明文'}
            >
              {showLocalApiKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            </button>
          </div>

          <div className="flex items-center justify-between text-[11px] text-slate-400 pt-1">
            <span>
              服务端绑定指纹: <span className="font-mono text-slate-600 dark:text-slate-300 font-semibold">{settings?.api_key_masked}</span>
            </span>
            <button
              type="submit"
              className="px-3.5 py-1 text-xs font-medium rounded-lg bg-slate-900 dark:bg-slate-100 text-white dark:text-slate-900 hover:bg-slate-800 transition"
            >
              更新本地 API Key
            </button>
          </div>
        </form>
      </div>

      {/* Main Settings Form */}
      <form onSubmit={handleSaveSettings} className="space-y-6">
        {/* Bark Notification Settings */}
        <div className="rounded-2xl bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800/80 p-5 shadow-sm space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <div className="p-2 rounded-xl bg-blue-100 dark:bg-blue-950/40 text-blue-600 dark:text-blue-400">
                <Bell className="w-4 h-4" />
              </div>
              <div>
                <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">Bark 告警通知</h2>
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  Cookie 凭证失效、或自动重试失败达最大上限时即时推送到 iOS 设备
                </p>
              </div>
            </div>

            <button
              type="button"
              onClick={handleTestBark}
              disabled={isTestingBark}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-xl border border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition disabled:opacity-40"
            >
              {isTestingBark ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Send className="w-3.5 h-3.5 text-blue-500" />}
              <span>发送测试通知</span>
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                Bark 服务端地址
              </label>
              <input
                type="text"
                required
                value={barkServer}
                onChange={(e) => setBarkServer(e.target.value)}
                placeholder="https://api.day.app"
                className="w-full px-3 py-2 text-xs font-mono rounded-xl border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 focus:ring-2 focus:ring-orange-500 focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                全局 Bark Device Key (敏感)
              </label>
              <div className="relative">
                <input
                  type={showBarkKey ? 'text' : 'password'}
                  value={barkKey}
                  onChange={(e) => setBarkKey(e.target.value)}
                  placeholder="例如：aB1c2D3e4F..."
                  className="w-full pl-3 pr-10 py-2 text-xs font-mono rounded-xl border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 focus:ring-2 focus:ring-orange-500 focus:outline-none"
                />
                <button
                  type="button"
                  onClick={() => setShowBarkKey(!showBarkKey)}
                  className="absolute inset-y-0 right-0 pr-3 flex items-center text-slate-400 hover:text-slate-600 dark:hover:text-slate-200"
                >
                  {showBarkKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Schedule & Retry Mechanism Settings */}
        <div className="rounded-2xl bg-white dark:bg-slate-900 border border-slate-200/80 dark:border-slate-800/80 p-5 shadow-sm space-y-4">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-xl bg-emerald-100 dark:bg-emerald-950/40 text-emerald-600 dark:text-emerald-400">
              <Clock className="w-4 h-4" />
            </div>
            <div>
              <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">每日定时调度、失败重试与延迟</h2>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                失败自动重试机制（达到上限后发 Bark 告警），模拟人类操作节奏
              </p>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div>
              <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                每日执行时间 (HH:mm)
              </label>
              <input
                type="text"
                required
                value={sparkTime}
                onChange={(e) => setSparkTime(e.target.value)}
                placeholder="09:30"
                className="w-full px-3 py-2 text-xs font-mono rounded-xl border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 focus:ring-2 focus:ring-orange-500 focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1 flex items-center gap-1">
                <RotateCcw className="w-3 h-3 text-orange-500" />
                <span>失败自动重试次数 (次)</span>
              </label>
              <input
                type="number"
                min={1}
                max={10}
                required
                value={maxRetries}
                onChange={(e) => setMaxRetries(Number(e.target.value))}
                className="w-full px-3 py-2 text-xs rounded-xl border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 focus:ring-2 focus:ring-orange-500 focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                最小随机延迟 (秒)
              </label>
              <input
                type="number"
                min={1}
                required
                value={minDelay}
                onChange={(e) => setMinDelay(Number(e.target.value))}
                className="w-full px-3 py-2 text-xs rounded-xl border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 focus:ring-2 focus:ring-orange-500 focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">
                最大随机延迟 (秒)
              </label>
              <input
                type="number"
                min={minDelay}
                required
                value={maxDelay}
                onChange={(e) => setMaxDelay(Number(e.target.value))}
                className="w-full px-3 py-2 text-xs rounded-xl border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 focus:ring-2 focus:ring-orange-500 focus:outline-none"
              />
            </div>
          </div>
        </div>

        {/* Submit */}
        <div className="flex items-center justify-end gap-3">
          {saveSuccess && (
            <span className="text-xs text-emerald-600 dark:text-emerald-400 flex items-center gap-1">
              <Check className="w-4 h-4" /> 配置已保存
            </span>
          )}
          <button
            type="submit"
            disabled={isSaving}
            className="flex items-center gap-1.5 px-5 py-2.5 text-xs font-semibold rounded-xl bg-orange-500 hover:bg-orange-600 text-white shadow-md shadow-orange-500/20 transition disabled:opacity-50"
          >
            {isSaving ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <ShieldCheck className="w-3.5 h-3.5" />}
            <span>保存全部配置</span>
          </button>
        </div>
      </form>
    </div>
  );
};
