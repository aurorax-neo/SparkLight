import React, { useState, useEffect } from 'react';
import {
  Flame,
  LayoutDashboard,
  Users,
  Sparkles,
  ScrollText,
  Settings,
  Play,
  Sun,
  Moon,
  Loader2,
  LogOut,
  Clock,
} from 'lucide-react';
import { api } from '../api/client';
import { useToast } from './ui/Toast';
import { ConfirmModal } from './ui/ConfirmModal';

export type TabType = 'dashboard' | 'accounts' | 'targets' | 'logs' | 'settings';

interface Props {
  activeTab: TabType;
  setActiveTab: (tab: TabType) => void;
  onTriggerRefresh: () => void;
  onLogout: () => void;
}

function formatCurrentDateTime(date: Date): string {
  const y = date.getFullYear();
  const m = String(date.getMonth() + 1).padStart(2, '0');
  const d = String(date.getDate()).padStart(2, '0');
  const hh = String(date.getHours()).padStart(2, '0');
  const mm = String(date.getMinutes()).padStart(2, '0');
  const ss = String(date.getSeconds()).padStart(2, '0');
  return `${y}年${m}月${d}日 ${hh}:${mm}:${ss}`;
}

export const Navbar: React.FC<Props> = ({
  activeTab,
  setActiveTab,
  onTriggerRefresh,
  onLogout,
}) => {
  const toast = useToast();
  const [isRunningAll, setIsRunningAll] = useState(false);
  const [isConfirmAllOpen, setIsConfirmAllOpen] = useState(false);
  const [isDark, setIsDark] = useState(() => document.documentElement.classList.contains('dark'));
  const [currentTimeStr, setCurrentTimeStr] = useState(() => formatCurrentDateTime(new Date()));

  // Live ticking clock every second
  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentTimeStr(formatCurrentDateTime(new Date()));
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  const toggleDarkMode = () => {
    const nextDark = !isDark;
    setIsDark(nextDark);
    if (nextDark) {
      document.documentElement.classList.add('dark');
      localStorage.setItem('sparklight_theme', 'dark');
    } else {
      document.documentElement.classList.remove('dark');
      localStorage.setItem('sparklight_theme', 'light');
    }
  };

  const handleRunAllConfirmed = async () => {
    setIsConfirmAllOpen(false);
    setIsRunningAll(true);
    try {
      const res = await api.runAll(false);
      if (res.data?.status === 'SUCCESS') toast.success(res.message || '全量任务正常结束');
      else if (res.data?.status === 'PARTIAL_FAILED') toast.info(res.message || '全量任务部分失败');
      else toast.error(res.message || '全量任务失败或结果未确认');
      onTriggerRefresh();
    } catch (e: any) {
      toast.error(`执行失败: ${e.message}`);
    } finally {
      setIsRunningAll(false);
    }
  };

  const tabs = [
    { id: 'dashboard', label: '系统概览', icon: LayoutDashboard },
    { id: 'accounts', label: '账号管理', icon: Users },
    { id: 'targets', label: '续火花目标', icon: Sparkles },
    { id: 'logs', label: '运行流水', icon: ScrollText },
    { id: 'settings', label: '系统设置', icon: Settings },
  ] as const;

  return (
    <>
      <header className="sticky top-0 z-30 w-full border-b border-slate-200/80 dark:border-slate-800/80 bg-white/80 dark:bg-slate-900/80 backdrop-blur-md">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-wrap xl:flex-nowrap items-center justify-between gap-x-4 gap-y-2 py-3 xl:py-0 xl:h-16">
          {/* Brand */}
          <div className="flex shrink-0 items-center gap-3">
            <div className="flex items-center justify-center w-10 h-10 rounded-xl bg-gradient-to-tr from-amber-500 via-orange-500 to-rose-500 text-white shadow-md shadow-orange-500/20">
              <Flame className="w-6 h-6 animate-pulse" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-lg tracking-tight bg-gradient-to-r from-orange-600 via-amber-600 to-rose-600 bg-clip-text text-transparent">
                  SparkLight
                </span>
                <span className="text-[10px] uppercase font-semibold px-2 py-0.5 rounded-full bg-orange-100 dark:bg-orange-900/30 text-orange-700 dark:text-orange-400 border border-orange-200 dark:border-orange-800/50">
                  火花守护者
                </span>
              </div>
              <p className="text-[11px] text-slate-500 dark:text-slate-400 hidden sm:block">
                多抖音账号隔离 · 每日自动续火花 · Bark告警
              </p>
            </div>
          </div>

          {/* Navigation Tabs */}
          <nav aria-label="主导航" className="order-last xl:order-none flex w-full xl:w-auto shrink-0 items-center gap-1 overflow-x-auto whitespace-nowrap bg-slate-100/80 dark:bg-slate-800/80 p-1 rounded-xl border border-slate-200/50 dark:border-slate-700/50">
            {tabs.map((tab) => {
              const Icon = tab.icon;
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  aria-current={isActive ? 'page' : undefined}
                  className={`flex shrink-0 items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                    isActive
                      ? 'bg-white dark:bg-slate-900 text-orange-600 dark:text-orange-400 shadow-sm'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200 hover:bg-white/50 dark:hover:bg-slate-700/50'
                  }`}
                >
                  <Icon className="w-3.5 h-3.5 shrink-0" />
                  <span>{tab.label}</span>
                </button>
              );
            })}
          </nav>

          {/* Right Action Controls: Live Clock & Action Buttons */}
          <div className="flex shrink-0 items-center gap-2.5 whitespace-nowrap">
            {/* Live Clock */}
            <div className="hidden 2xl:flex shrink-0 items-center gap-1.5 px-2.5 py-1.5 rounded-xl border border-slate-200/70 dark:border-slate-800/70 bg-slate-50/70 dark:bg-slate-800/50 text-slate-600 dark:text-slate-300 font-mono tabular-nums text-[11px]">
              <Clock className="w-3.5 h-3.5 text-orange-500 animate-spin-slow" />
              <span>{currentTimeStr}</span>
            </div>

            <button
              onClick={() => setIsConfirmAllOpen(true)}
              disabled={isRunningAll}
              aria-label="立即执行"
              className="flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-medium rounded-xl bg-orange-500 hover:bg-orange-600 active:scale-95 text-white transition shadow-sm shadow-orange-500/30 disabled:opacity-50"
            >
              {isRunningAll ? (
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
              ) : (
                <Play className="w-3.5 h-3.5 fill-current" />
              )}
              <span className="hidden sm:inline">立即执行</span>
            </button>

            <button
              onClick={toggleDarkMode}
              className="p-2 rounded-xl border border-slate-200 dark:border-slate-800 text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 transition"
              title="切换深浅主题"
            >
              {isDark ? <Sun className="w-4 h-4 text-amber-400" /> : <Moon className="w-4 h-4 text-slate-600" />}
            </button>

            <button
              onClick={onLogout}
              className="p-2 rounded-xl border border-rose-200 dark:border-rose-900/50 bg-rose-50/50 dark:bg-rose-950/20 text-rose-600 dark:text-rose-400 hover:bg-rose-100 dark:hover:bg-rose-900/40 transition"
              title="退出登录"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        </div>
      </header>

      <ConfirmModal
        isOpen={isConfirmAllOpen}
        title="全量续火花确认"
        description="系统将按设置的随机延迟依次对所有活跃账号的续火花目标执行消息互动，若今日已有互动记录则自动跳过。是否确认立即触发？"
        confirmText="立即执行"
        onConfirm={handleRunAllConfirmed}
        onCancel={() => setIsConfirmAllOpen(false)}
      />
    </>
  );
};
