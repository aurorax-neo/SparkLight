import React, { useState } from 'react';
import { KeyRound, ShieldCheck, X } from 'lucide-react';
import { ModalPortal } from './ui/ModalPortal';
import { getStoredApiKey, setStoredApiKey } from '../api/client';

interface Props {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
}

export const ApiKeyModal: React.FC<Props> = ({ isOpen, onClose, onSuccess }) => {
  const [apiKey, setApiKey] = useState(getStoredApiKey());
  const [error, setError] = useState('');

  if (!isOpen) return null;

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    if (!apiKey.trim()) {
      setError('请输入有效的 API Key');
      return;
    }
    setStoredApiKey(apiKey.trim());
    setError('');
    onSuccess();
    onClose();
  };

  return (
    <ModalPortal>
      <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="relative w-full max-w-md rounded-2xl bg-white dark:bg-slate-900 p-6 shadow-2xl border border-slate-200 dark:border-slate-800 animate-in fade-in zoom-in-95 duration-150">
        <button
          onClick={onClose}
          className="absolute right-4 top-4 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200"
        >
          <X className="w-5 h-5" />
        </button>

        <div className="flex items-center gap-3 mb-4">
          <div className="p-2.5 rounded-xl bg-orange-500/10 text-orange-500 dark:bg-orange-500/20">
            <KeyRound className="w-6 h-6" />
          </div>
          <div>
            <h3 className="text-lg font-semibold text-slate-900 dark:text-slate-100">配置访问 API Key</h3>
            <p className="text-xs text-slate-500 dark:text-slate-400">后端接口需携带认证 Key 访问</p>
          </div>
        </div>

        <form onSubmit={handleSave} className="space-y-4">
          <div>
            <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1.5">
              API Key (格式如 sk_...)
            </label>
            <input
              type="text"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder="请输入服务端启动时输出的 API Key"
              className="w-full px-3.5 py-2.5 text-sm rounded-xl border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-orange-500"
              autoFocus
            />
            {error && <p className="text-xs text-rose-500 mt-1">{error}</p>}
            <p className="text-xs text-slate-400 dark:text-slate-500 mt-2">
              首次启动时会在终端打印自动生成的系统 API Key，亦可在环境变量 SPARK_API_KEY 中指定。
            </p>
          </div>

          <div className="flex gap-2.5 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="flex-1 px-4 py-2.5 text-sm font-medium rounded-xl border border-slate-200 dark:border-slate-800 text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition"
            >
              取消
            </button>
            <button
              type="submit"
              className="flex-1 flex items-center justify-center gap-1.5 px-4 py-2.5 text-sm font-medium rounded-xl bg-orange-500 hover:bg-orange-600 text-white shadow-lg shadow-orange-500/20 transition"
            >
              <ShieldCheck className="w-4 h-4" />
              保存并连接
            </button>
          </div>
        </form>
      </div>
      </div>
    </ModalPortal>
  );
};
