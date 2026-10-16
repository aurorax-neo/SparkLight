import React, { useEffect, useLayoutEffect, useRef, useState } from 'react';
import { Navbar, TabType } from './components/Navbar';
import { LoginPage } from './pages/LoginPage';
import { DashboardPage } from './pages/DashboardPage';
import { AccountsPage } from './pages/AccountsPage';
import { TargetsPage } from './pages/TargetsPage';
import { LogsPage } from './pages/LogsPage';
import { SettingsPage } from './pages/SettingsPage';
import { ToastProvider } from './components/ui/Toast';
import { ConfirmModal } from './components/ui/ConfirmModal';
import { getStoredApiKey, setOnAuthError, setStoredApiKey } from './api/client';

const VALID_TABS: TabType[] = ['dashboard', 'accounts', 'targets', 'logs', 'settings'];

function getInitialTab(): TabType {
  const hash = window.location.hash.replace('#', '') as TabType;
  if (VALID_TABS.includes(hash)) {
    return hash;
  }
  const saved = localStorage.getItem('sparklight_active_tab') as TabType;
  if (VALID_TABS.includes(saved)) {
    return saved;
  }
  return 'dashboard';
}

const AppContent: React.FC = () => {
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(() => {
    return Boolean(getStoredApiKey());
  });
  const [activeTab, setActiveTabState] = useState<TabType>(getInitialTab);
  const [visitedTabs, setVisitedTabs] = useState<Set<TabType>>(() => new Set([activeTab]));
  const previousTab = useRef(activeTab);
  const tabScroll = useRef<Partial<Record<TabType, number>>>({});
  const [refreshTrigger, setRefreshTrigger] = useState(0);
  const [isLogoutConfirmOpen, setIsLogoutConfirmOpen] = useState(false);

  const handleTabChange = (tab: TabType) => {
    if (tab === activeTab) return;
    tabScroll.current[activeTab] = window.scrollY;
    setVisitedTabs((tabs) => new Set(tabs).add(tab));
    setActiveTabState(tab);
    localStorage.setItem('sparklight_active_tab', tab);
    window.location.hash = tab;
  };

  useEffect(() => {
    setOnAuthError(() => {
      setStoredApiKey('');
      setIsAuthenticated(false);
    });

    const savedTheme = localStorage.getItem('sparklight_theme');
    if (savedTheme === 'dark' || (!savedTheme && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }

    const onHashChange = () => {
      const hash = window.location.hash.replace('#', '') as TabType;
      if (VALID_TABS.includes(hash)) {
        setActiveTabState(hash);
      }
    };
    const rememberScroll = () => {
      tabScroll.current[previousTab.current] = window.scrollY;
    };
    window.addEventListener('scroll', rememberScroll, { passive: true });
    window.addEventListener('hashchange', onHashChange);
    return () => {
      window.removeEventListener('hashchange', onHashChange);
      window.removeEventListener('scroll', rememberScroll);
    };
  }, []);

  useLayoutEffect(() => {
    setVisitedTabs((tabs) => tabs.has(activeTab) ? tabs : new Set(tabs).add(activeTab));
    previousTab.current = activeTab;
    window.scrollTo({ top: tabScroll.current[activeTab] ?? 0, behavior: 'instant' });
  }, [activeTab]);

  const handleLogout = () => {
    setIsLogoutConfirmOpen(true);
  };

  const handleConfirmLogout = () => {
    setStoredApiKey('');
    setIsAuthenticated(false);
    setIsLogoutConfirmOpen(false);
  };

  const triggerRefresh = () => {
    setRefreshTrigger((prev) => prev + 1);
  };

  if (!isAuthenticated) {
    return (
      <LoginPage
        onLoginSuccess={() => {
          setIsAuthenticated(true);
          triggerRefresh();
        }}
      />
    );
  }

  return (
    <div className="min-h-screen flex flex-col bg-slate-50 dark:bg-slate-950">
      <Navbar
        activeTab={activeTab}
        setActiveTab={handleTabChange}
        onTriggerRefresh={triggerRefresh}
        onLogout={handleLogout}
      />

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {VALID_TABS.filter((tab) => visitedTabs.has(tab) || tab === activeTab).map((tab) => (
          <section key={tab} hidden={activeTab !== tab} aria-label={tab}>
            {tab === 'dashboard' && (
              <DashboardPage active={activeTab === tab} onNavigate={handleTabChange} refreshTrigger={refreshTrigger} />
            )}
            {tab === 'accounts' && (
              <AccountsPage active={activeTab === tab} refreshTrigger={refreshTrigger} onRefresh={triggerRefresh} />
            )}
            {tab === 'targets' && (
              <TargetsPage active={activeTab === tab} refreshTrigger={refreshTrigger} onRefresh={triggerRefresh} />
            )}
            {tab === 'logs' && <LogsPage active={activeTab === tab} refreshTrigger={refreshTrigger} />}
            {tab === 'settings' && <SettingsPage onApiKeyUpdated={triggerRefresh} />}
          </section>
        ))}
      </main>

      <ConfirmModal
        isOpen={isLogoutConfirmOpen}
        title="确认退出登录"
        description="退出登录后将清除本地会话缓存，需要重新输入 API Key 访问。"
        confirmText="退出登录"
        isDanger={true}
        onConfirm={handleConfirmLogout}
        onCancel={() => setIsLogoutConfirmOpen(false)}
      />
    </div>
  );
};

export const App: React.FC = () => {
  return (
    <ToastProvider>
      <AppContent />
    </ToastProvider>
  );
};
