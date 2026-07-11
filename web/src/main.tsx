import React from 'react';
import ReactDOM from 'react-dom/client';
import { ConfigProvider } from 'antd';
import zhCN from 'antd/locale/zh_CN';
import { BrowserRouter } from 'react-router-dom';

import { AuthProvider } from './auth/AuthProvider';
import { App } from './App';
import './i18n';
import './styles.css';

ReactDOM.createRoot(document.getElementById('root') as HTMLElement).render(
  <React.StrictMode>
    <ConfigProvider
      locale={zhCN}
      theme={{
        token: {
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
        },
        components: {
          Layout: { colorBgHeader: 'rgba(255,255,255,0.92)', colorBgBody: '#f8fafc' },
          Card: { borderRadiusLG: 8, colorBorder: '#e2e8f0' },
          Button: { borderRadius: 8, controlHeight: 34 },
          Input: { borderRadius: 8, controlHeight: 34 },
          Table: { borderRadius: 8, headerBg: '#f8fafc', headerColor: '#475569', rowHoverBg: '#f1f5f9' },
          Tabs: { itemSelectedColor: '#165dff', inkBarColor: '#165dff' },
          Pagination: { itemActiveBg: '#e8f3ff' },
          Menu: { itemSelectedBg: '#e8f3ff', itemSelectedColor: '#165dff' },
          Tag: { borderRadiusSM: 6 }
        }
      }}
    >
      <BrowserRouter>
        <AuthProvider>
          <App />
        </AuthProvider>
      </BrowserRouter>
    </ConfigProvider>
  </React.StrictMode>
);
