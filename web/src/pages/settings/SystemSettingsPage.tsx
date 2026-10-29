import { Empty } from 'antd';
import { ChevronRight } from 'lucide-react';
import { Link } from 'react-router-dom';

import { useAuth } from '../../auth/AuthProvider';
import { PageHeader } from '../../components/PageHeader';
import { platformSettingsEntries } from '../../layouts/platformSettings';

export function SystemSettingsPage() {
  const { can } = useAuth();
  const entries = platformSettingsEntries.filter((entry) => can(entry.permission));
  return <section className="page-surface">
    <PageHeader title="系统设置" subtitle="集中管理平台配置、用户与权限。项目的 SLA 和通知规则在项目菜单中设置。" />
    {entries.length ? <nav className="system-settings-list" aria-label="系统设置功能">
      {entries.map((entry) => <Link className="system-settings-link" key={entry.path} to={entry.path}>
        <div><h3>{entry.name}</h3><p>{entry.description}</p></div>
        <ChevronRight size={18} aria-hidden="true" />
      </Link>)}
    </nav> : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="当前账号没有平台管理权限，请联系系统管理员。">
      <Link to="/workspace">查看全局工作台</Link>
    </Empty>}
  </section>;
}
