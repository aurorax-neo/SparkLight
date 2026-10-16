import React, { useState } from 'react';
import { Flame, ShieldCheck, KeyRound, Eye, EyeOff, Loader2 } from 'lucide-react';
import { api, setStoredApiKey } from '../api/client';

interface Props {
  onLoginSuccess: () => void;
}

export const LoginPage: React.FC<Props> = ({ onLoginSuccess }) => {
  const [apiKey, setApiKey] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isVerifying, setIsVerifying] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const cleanKey = apiKey.trim();
    if (!cleanKey) {
      setError('请输入管理 API Key');
      return;
    }

    setIsVerifying(true);
    setError('');

    try {
      // Temporarily store to test endpoint with X-API-Key header
      setStoredApiKey(cleanKey);
      await api.getOverview();
      // Verified successfully!
      onLoginSuccess();
    } catch (err: any) {
      setStoredApiKey('');
      setError(err.message || 'API Key 校验失败，请检查是否填写正确');
    } finally {
      setIsVerifying(false);
    }
  };

  return (
    <div className="min-h-screen w-full flex items-center justify-center p-4 bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100">
      <div className="w-full max-w-md rounded-2xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 p-6 sm:p-8 shadow-sm">
        {/* Brand Header */}
        <div className="flex flex-col items-center text-center mb-8">
          <div className="flex items-center justify-center w-14 h-14 rounded-2xl bg-gradient-to-tr from-amber-500 via-orange-500 to-rose-500 text-white shadow-xl shadow-orange-500/25 mb-4">
            <Flame className="w-8 h-8" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-orange-600 dark:text-orange-400">
            SparkLight
          </h1>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1.5">
            抖音多账号隔离维护 · 每日续火花系统
          </p>
        </div>

        {/* Login Form */}
        <form onSubmit={handleSubmit} className="space-y-5">
          <div>
            <label htmlFor="management-api-key" className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-2">
              管理员 API Key
            </label>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
                <KeyRound className="w-4 h-4" />
              </div>
              <input
                id="management-api-key"
                autoComplete="off"
                aria-invalid={Boolean(error)}
                aria-describedby={error ? 'login-error' : undefined}
                type={showPassword ? 'text' : 'password'}
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                placeholder="请输入 sk_..."
                autoFocus
                className="w-full pl-10 pr-10 py-3 text-sm rounded-xl border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-orange-500 focus:border-transparent transition"
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                aria-label={showPassword ? '隐藏密钥' : '显示密钥'}
                aria-pressed={showPassword}
                className="absolute inset-y-0 right-0 pr-3 flex items-center text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200 focus-visible:outline-orange-500"
              >
                {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
            {error && (
              <p id="login-error" role="alert" className="text-xs text-rose-600 dark:text-rose-400 mt-2">
                <span>{error}</span>
              </p>
            )}
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-2">使用管理员提供的 API Key 连接。</p>
          </div>

          <button
            type="submit"
            disabled={isVerifying}
            className="w-full flex items-center justify-center gap-2 py-3 px-4 rounded-xl text-sm font-semibold bg-orange-500 hover:bg-orange-600 text-white transition focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-orange-500 disabled:opacity-60"
          >
            {isVerifying ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                <span>正在验证密钥...</span>
              </>
            ) : (
              <>
                <ShieldCheck className="w-4 h-4" />
                <span>安全连接控制台</span>
              </>
            )}
          </button>
        </form>

        <div className="mt-8 pt-4 border-t border-slate-200 dark:border-slate-800 text-center">
          <p className="text-xs text-slate-500 dark:text-slate-400">SparkLight 管理控制台</p>
        </div>
      </div>
    </div>
  );
};
