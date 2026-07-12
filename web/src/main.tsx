import React from 'react';
import ReactDOM from 'react-dom/client';
import { ConfigProvider, theme as antTheme } from 'antd';
import zhCN from 'antd/locale/zh_CN';
import { BrowserRouter } from 'react-router-dom';

import { AuthProvider } from './auth/AuthProvider';
import { App } from './App';
import { useThemeStore } from './stores/themeStore';
import './i18n';
import './styles.css';

const lightTokens = {
  borderRadius: 8,
  colorPrimary: '#165dff',
  colorInfo: '#165dff',
  colorLink: '#165dff',
  colorBgBase: '#f8fafc',
  colorBgLayout: '#f8fafc',
  colorBgContainer: '#ffffff',
  colorBorder: '#e2e8f0',
  colorBorderSecondary: '#f1f5f9',
  colorTextSecondary: '#64748b',
  fontFamily: 'PingFang SC, Microsoft YaHei, Noto Sans SC, Inter, ui-sans-serif, system-ui, sans-serif'
};

const darkTokens = {
  borderRadius: 8,
  colorPrimary: '#3b82f6',
  colorInfo: '#3b82f6',
  colorLink: '#3b82f6',
  colorBgBase: '#090d16',
  colorBgLayout: '#090d16',
  colorBgContainer: '#0f172a',
  colorBorder: '#1e293b',
  colorBorderSecondary: '#1e293b',
  colorTextSecondary: '#94a3b8',
  fontFamily: 'PingFang SC, Microsoft YaHei, Noto Sans SC, Inter, ui-sans-serif, system-ui, sans-serif'
};

const lightComponents = {
  Layout: { colorBgHeader: 'rgba(255,255,255,0.92)', colorBgBody: '#f8fafc' },
  Card: { borderRadiusLG: 8, colorBorder: '#e2e8f0' },
  Button: { borderRadius: 8, controlHeight: 34 },
  Input: { borderRadius: 8, controlHeight: 34 },
  Table: { borderRadius: 8, headerBg: '#f8fafc', headerColor: '#475569', rowHoverBg: '#f1f5f9' },
  Tabs: { itemSelectedColor: '#165dff', inkBarColor: '#165dff' },
  Pagination: { itemActiveBg: '#e8f3ff' },
  Menu: { itemSelectedBg: '#e8f3ff', itemSelectedColor: '#165dff' },
  Tag: { borderRadiusSM: 6 }
};

const darkComponents = {
  Layout: { colorBgHeader: 'rgba(15, 23, 42, 0.85)', colorBgBody: '#090d16' },
  Card: { borderRadiusLG: 8, colorBorder: '#1e293b' },
  Button: { borderRadius: 8, controlHeight: 34 },
  Input: { borderRadius: 8, controlHeight: 34 },
  Table: { borderRadius: 8, headerBg: '#1e293b', headerColor: '#f8fafc', rowHoverBg: '#111a2e' },
  Tabs: { itemSelectedColor: '#3b82f6', inkBarColor: '#3b82f6' },
  Pagination: { itemActiveBg: 'rgba(59, 130, 246, 0.15)' },
  Menu: { itemSelectedBg: 'rgba(59, 130, 246, 0.15)', itemSelectedColor: '#3b82f6' },
  Tag: { borderRadiusSM: 6 }
};

function ThemedApp() {
  const mode = useThemeStore((s) => s.mode);
  return (
    <ConfigProvider
      locale={zhCN}
      theme={{
        algorithm: mode === 'dark' ? antTheme.darkAlgorithm : antTheme.defaultAlgorithm,
        token: mode === 'dark' ? darkTokens : lightTokens,
        components: mode === 'dark' ? darkComponents : lightComponents
      }}
    >
      <BrowserRouter>
        <AuthProvider>
          <App />
        </AuthProvider>
      </BrowserRouter>
    </ConfigProvider>
  );
}

ReactDOM.createRoot(document.getElementById('root') as HTMLElement).render(
  <React.StrictMode>
    <ThemedApp />
  </React.StrictMode>
);
