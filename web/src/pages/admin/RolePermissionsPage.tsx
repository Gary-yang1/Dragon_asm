import { Table, Tag } from 'antd';
import { useCallback, useEffect, useState } from 'react';

import { listAdminRoles, type AdminRole } from '../../api/platform';
import { errorMessage } from '../../api/errorMessage';
import { PageHeader } from '../../components/PageHeader';
import { StateView } from '../../components/StateView';

export function RolePermissionsPage() {
  const [roles, setRoles] = useState<AdminRole[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    setLoading(true);
    setError(null);
    void listAdminRoles()
      .then(setRoles)
      .catch((reason) => setError(errorMessage(reason)))
      .finally(() => setLoading(false));
  }, []);

  useEffect(load, [load]);

  return (
    <section className="page-surface">
      <PageHeader title="角色权限" subtitle="固定角色矩阵（只读）；平台角色与项目角色分开授权" />
      <StateView
        loading={loading}
        error={error}
        empty={!loading && !error && roles.length === 0}
        emptyText="暂无角色定义"
        onRetry={load}
      >
        <Table<AdminRole>
          rowKey="value"
          dataSource={roles}
          pagination={false}
          columns={[
            { title: '角色', dataIndex: 'label', width: 160 },
            {
              title: '作用域',
              dataIndex: 'scope',
              width: 120,
              render: (scope: AdminRole['scope']) => <Tag color={scope === 'tenant' ? 'blue' : 'default'}>{scope === 'tenant' ? '平台' : '项目'}</Tag>
            },
            {
              title: '权限点',
              dataIndex: 'permissions',
              render: (permissions: string[]) => permissions.map((permission) => <Tag key={permission}>{permission}</Tag>)
            }
          ]}
        />
      </StateView>
    </section>
  );
}
