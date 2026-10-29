import { ProLayout } from '@ant-design/pro-components';
import { Alert, Avatar, Button, Dropdown, Input, Space, Tooltip } from 'antd';
import { BarChart3, Bell, ChevronDown, ChevronLeft, ChevronRight, ClipboardList, FolderKanban, LayoutDashboard, LogOut, Moon, Radar, Server, Settings, ShieldCheck, SlidersHorizontal, Sun } from 'lucide-react';
import { useCallback, useEffect, useMemo, useState, type ReactElement } from 'react';
import { Outlet, useLocation, useNavigate } from 'react-router-dom';

import { useAuth } from '../auth/AuthProvider';
import { Permission } from '../auth/permissions';
import { platformSettingsEntries } from './platformSettings';
import { useProjectNavigation } from './useProjectNavigation';
import { ProjectStatusBanner } from '../components/ProjectStatusGate';
import { sanitizeDisplayName } from '../utils/text';
import { listProjects, type Project } from '../api/projects';
import { useThemeStore } from '../stores/themeStore';

export function AppLayout() {
  const navigate = useNavigate();
  const location = useLocation();
  const toggleMode = useThemeStore((s) => s.toggleMode);
  const themeMode = useThemeStore((s) => s.mode);
  const { user, logout, can: canGlobal } = useAuth();
  const navigation = useProjectNavigation();
  const { clear: clearProjectNavigation } = navigation;
  const [globalQuery, setGlobalQuery] = useState('');
  useEffect(() => { setGlobalQuery(new globalThis.URLSearchParams(location.search).get('q') ?? ''); }, [location.pathname, location.search]);
  const [projects, setProjects] = useState<Project[]>([]);
  const [collapsed, setCollapsed] = useState(false);
  const projectId = navigation.projectId;
  const projectPrefix = projectId ? `/projects/${projectId}` : '';
  const selectedProject = projects.find((project) => project.id === projectId);
  const routes = useMemo(() => {
    const platformRoutes = [
      { path: '/platform/settings', name: '设置中心' },
      ...platformSettingsEntries.filter((entry) => canGlobal(entry.permission)).map(({ path, name }) => ({ path, name }))
    ];
    const globalItems = [
      { path: '/workspace', name: '工作台', icon: <LayoutDashboard size={16} /> },
      { path: '/projects', name: '项目', icon: <FolderKanban size={16} /> },
      { path: '/work-items', name: '我的待办', icon: <ClipboardList size={16} /> },
      ...(platformRoutes.length > 0
        ? [{
            path: '/platform',
            name: '系统设置',
            icon: <ShieldCheck size={16} />,
            routes: platformRoutes
          }]
        : [])
    ];
    if (!projectId) return globalItems;

    const projectItems: Array<{ path: string; name: string; icon: ReactElement; permission: Permission }> = [
      { path: `${projectPrefix}/overview`, name: '项目概览', icon: <LayoutDashboard size={16} />, permission: Permission.ReportRead },
      { path: `${projectPrefix}/profile`, name: '项目资料', icon: <SlidersHorizontal size={16} />, permission: Permission.ProjectRead },
      { path: `${projectPrefix}/assets`, name: '资产管理', icon: <Server size={16} />, permission: Permission.AssetRead },
      { path: `${projectPrefix}/discovery`, name: '暴露发现', icon: <Radar size={16} />, permission: Permission.DiscoveryRead },
      { path: `${projectPrefix}/risks`, name: '风险管理', icon: <Bell size={16} />, permission: Permission.RiskRead },
      { path: `${projectPrefix}/tickets`, name: '工单管理', icon: <ClipboardList size={16} />, permission: Permission.TicketRead },
      { path: `${projectPrefix}/reports`, name: '报表中心', icon: <BarChart3 size={16} />, permission: Permission.ReportRead },
      { path: `${projectPrefix}/settings`, name: '项目设置', icon: <Settings size={16} />, permission: Permission.AdminManage }
    ];

    return [
      { path: '/workspace', name: '返回全局工作台', icon: <ChevronLeft size={16} /> },
      ...projectItems
        .filter((item) => navigation.loading || navigation.permissions?.includes(item.permission))
        .map((item) => ({ ...item, disabled: navigation.loading })),
      ...(platformRoutes.length ? [{ path: '/platform', name: '系统设置', icon: <ShieldCheck size={16} />, routes: platformRoutes }] : [])
    ];
  }, [canGlobal, navigation.loading, navigation.permissions, projectId, projectPrefix]);

  const loadProjects = useCallback(() => {
    let active = true;
    void listProjects(1, 100)
      .then((page) => { if (active) setProjects(page.items); })
      .catch(() => { if (active) setProjects([]); });
    return () => { active = false; };
  }, []);

  useEffect(() => {
    let cancel = loadProjects();
    const handleProjectsChanged = () => {
      cancel();
      cancel = loadProjects();
    };
    globalThis.addEventListener('asm:projects-changed', handleProjectsChanged);
    return () => {
      cancel();
      globalThis.removeEventListener('asm:projects-changed', handleProjectsChanged);
    };
  }, [loadProjects]);

  const userLabel = useMemo(() => {
    const raw = sanitizeDisplayName(user?.displayName || user?.username || '用户');
    const compacted = raw.replace(/\s+/g, ' ').trim();
    if (!compacted) return '用户';
    if (compacted.length > 18) return `${compacted.slice(0, 18)}…`;
    return compacted;
  }, [user?.displayName, user?.username]);

  const userInitial = useMemo(() => {
    const normalized = sanitizeDisplayName(userLabel.replace('…', '').trim());
    const first = [...normalized][0] ?? 'U';
    return /[A-Za-z0-9]/.test(first) ? first.toUpperCase() : first;
  }, [userLabel]);

  const dropdownItems = useMemo(() => {
    return [
      {
        key: 'all',
        label: '返回全局工作台',
      },
      ...(canGlobal(Permission.ProjectCreate) ? [{
        key: 'create',
        label: '创建新项目',
      }] : []),
      { type: 'divider' as const },
      ...projects.map(p => ({
        key: String(p.id),
        label: p.name,
      }))
    ];
  }, [canGlobal, projects]);

  const handleDropdownClick = useCallback(({ key }: { key: string }) => {
    if (key === 'all') {
      clearProjectNavigation();
      navigate('/workspace');
      return;
    }
    if (key === 'create') {
      clearProjectNavigation();
      navigate('/projects/new');
      return;
    }
    const nextProjectId = Number(key);
    localStorage.setItem('asm.lastProject', String(nextProjectId));
    navigate(`/projects/${nextProjectId}/overview`);
  }, [navigate, clearProjectNavigation]);

  const jumpToSearchPage = useCallback((value: string) => {
    const keyword = value.trim();
    if (!keyword) return;

    const lower = keyword.toLowerCase();
    const hasChinese = /[\u4e00-\u9fa5]/.test(keyword);

    const prefix = lower.match(/^(a|asset|r|risk|t|ticket):/)?.[1];
    const target = (() => {
      if (prefix) {
        const section = prefix === 'r' || prefix === 'risk' ? 'risks' : prefix === 't' || prefix === 'ticket' ? 'tickets' : 'assets';
        return projectId ? `${projectPrefix}/${section}` : '/projects';
      }
      if (lower.startsWith('a:') || lower.startsWith('asset:') || lower.includes('资产') || lower.includes('域名') || lower.includes('ip') || lower.includes('端口')) {
        return projectId ? `${projectPrefix}/assets` : '/projects';
      }
      if (
        lower.startsWith('r:') ||
        lower.startsWith('risk:') ||
        lower.includes('risk') ||
        lower.includes('风险') ||
        (hasChinese && lower.includes('cve'))
      ) {
        return projectId ? `${projectPrefix}/risks` : '/projects';
      }
      if (lower.startsWith('t:') || lower.startsWith('ticket:') || lower.includes('工单') || lower.includes('ticket')) {
        return projectId ? `${projectPrefix}/tickets` : '/projects';
      }
      const currentSection = location.pathname.endsWith('/risks') ? 'risks' : location.pathname.endsWith('/tickets') ? 'tickets' : 'assets';
      return projectId ? `${projectPrefix}/${currentSection}` : '/projects';
    })();

    const nextKeyword = keyword.replace(/^(?:[art]|asset|risk|ticket):\s*/i, '').trim();
    const params = new globalThis.URLSearchParams();
    if (nextKeyword) params.set('q', nextKeyword);
    const query = params.toString();
    const destination = `${target}${query ? `?${query}` : ''}`;
    navigate(destination);
  }, [location.pathname, navigate, projectId, projectPrefix]);

  return (
      <ProLayout
        className="asm-app-layout"
        title="ArgusASM"
        logo={<img src="/asmlogo.png" alt="ArgusASM Logo" className="layout-brand-logo-img" />}
        location={{ pathname: location.pathname }}
        route={{ path: '/', routes }}
        menuHeaderRender={(logo) => (
          <Dropdown
            menu={{
              items: dropdownItems,
              onClick: handleDropdownClick,
            }}
            trigger={['click']}
            placement="bottomLeft"
          >
            <button type="button" className="layout-brand-dropdown-trigger" aria-label={projectId ? `切换项目：${selectedProject?.name ?? `项目 ${projectId}`}` : '选择项目'}>
              {logo}
              <div className="brand-text-wrapper">
                <div className="brand-project-title-row">
                  <span className="brand-project-title">
                    {projectId ? (selectedProject?.name ?? `项目 ${projectId}`) : '全局工作台'}
                  </span>
                  <ChevronDown size={12} className="brand-project-chevron" />
                </div>
                <div className="brand-project-subtitle">ArgusASM 攻击面平台</div>
              </div>
            </button>
          </Dropdown>
        )}
        menuItemRender={(item, dom) => (
          <div
            role="button"
            tabIndex={item.disabled ? -1 : 0}
            aria-disabled={item.disabled || undefined}
            className={`menu-link ${isMenuPathActive(location.pathname, item.path) ? 'menu-link-active' : ''}`}
            aria-current={isMenuPathActive(location.pathname, item.path) ? 'page' : undefined}
            onClick={() => {
              if (!item.path || item.disabled) return;
              if (item.path === '/workspace') clearProjectNavigation();
              navigate(item.path);
            }}
            onKeyDown={(event) => {
              if (event.key === 'Enter' || event.key === ' ') {
                event.preventDefault();
                if (item.path && !item.disabled) {
                  if (item.path === '/workspace') clearProjectNavigation();
                  navigate(item.path);
                }
              }
            }}
          >
            {dom}
          </div>
        )}
      collapsed={collapsed}
      onCollapse={setCollapsed}
      avatarProps={false}
      layout="side"
      siderWidth={216}
      fixSiderbar
      contentStyle={{ padding: 0 }}
      menu={{ collapsedShowTitle: false }}
      collapsedButtonRender={() => (
        <Tooltip title={collapsed ? '展开' : '收起'} placement="right">
          <div
            role="button"
            tabIndex={0}
            className="layout-collapse-toggle"
            aria-label={collapsed ? '展开侧边栏' : '收起侧边栏'}
            onClick={() => setCollapsed(!collapsed)}
            onKeyDown={(event) => {
              if (event.key === 'Enter' || event.key === ' ') {
                event.preventDefault();
                setCollapsed(!collapsed);
              }
            }}
          >
            {collapsed ? <ChevronRight size={14} /> : <ChevronLeft size={14} />}
          </div>
        </Tooltip>
      )}
    >
      <div className="layout-content-shell">
        <header className="app-topbar">
          <div className="app-topbar-project">
            {projectId
              ? <span className="app-topbar-title">{selectedProject?.name ?? `项目 ${projectId}`}<span className="workspace-context-label">{navigation.inPlatform ? '系统设置 · 全局' : '项目工作区'}</span></span>
              : <span className="app-topbar-title">{navigation.inPlatform ? '系统设置 · 全局' : '全局工作台'}</span>}
          </div>
          <Space className="layout-top-actions" align="center" size={8}>
            <Input.Search
              className="layout-global-search"
              aria-label="全局搜索"
              size="middle"
              placeholder="搜索资产 / 风险 / 工单"
              allowClear
              value={globalQuery}
              onChange={(event) => setGlobalQuery(event.target.value)}
              onSearch={(value) => jumpToSearchPage(value)}
            />
            <span className="layout-top-divider" aria-hidden="true" />
            <Tooltip title={themeMode === 'dark' ? '浅色模式' : '深色模式'}>
              <Button
                aria-label="切换主题"
                type="text"
                className="layout-top-action"
                icon={themeMode === 'dark' ? <Sun size={16} /> : <Moon size={16} />}
                onClick={toggleMode}
              />
            </Tooltip>
            <Tooltip title="通知规则">
              <Button
                aria-label="通知规则"
                type="text"
                className="layout-top-action"
                icon={<Bell size={16} />}
                onClick={() => navigate(projectId ? `${projectPrefix}/settings` : '/projects')}
              />
            </Tooltip>
            <Tooltip title="系统设置">
              <Button
                aria-label="系统设置"
                type="text"
                className="layout-top-action"
                icon={<Settings size={16} />}
                onClick={() => navigate('/platform/settings')}
              />
            </Tooltip>
            <Dropdown
              trigger={['click']}
              placement="bottomRight"
              menu={{
                items: [
                  {
                    key: 'logout',
                    danger: true,
                    icon: <LogOut size={15} />,
                    label: '退出登录'
                  }
                ],
                onClick: ({ key }) => {
                  if (key === 'logout') {
                    clearProjectNavigation();
                    logout();
                    navigate('/login', { replace: true });
                  }
                }
              }}
            >
              <button type="button" className="layout-user-trigger" aria-label={`当前用户：${userLabel}`}>
                <Avatar size={28} style={{ backgroundColor: 'var(--asm-primary)' }}>
                  {userInitial}
                </Avatar>
                <span className="layout-top-user-name" title={userLabel}>
                  {userLabel}
                </span>
                <ChevronDown size={14} aria-hidden="true" />
              </button>
            </Dropdown>
          </Space>
        </header>
        <main className="app-main">
          {navigation.inPlatform && projectId > 0 && <div className="project-return-bar">
            <span>当前为全局系统设置，项目工作区已保留。</span>
            <Button disabled={!navigation.returnPath} onClick={() => navigation.returnPath && navigate(navigation.returnPath)}>返回项目工作区</Button>
          </div>}
          {navigation.error && <Alert className="list-error-alert" type="warning" showIcon message={navigation.error} action={<Button onClick={navigation.retry}>重试</Button>} />}
          <ProjectStatusBanner />
          <Outlet />
        </main>
      </div>
    </ProLayout>
  );
}

function isMenuPathActive(pathname: string, menuPath?: string) {
  if (!menuPath) return false;
  if (menuPath === '/projects') {
    return pathname === '/projects' || pathname === '/projects/new';
  }
  return pathname === menuPath || pathname.startsWith(`${menuPath}/`);
}
