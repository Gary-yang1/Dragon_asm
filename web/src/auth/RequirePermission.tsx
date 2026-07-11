import { Navigate } from 'react-router-dom';
import { Spin } from 'antd';
import type { ReactNode } from 'react';

import { Permission } from './permissions';
import { usePermission } from './usePermission';

export function RequirePermission({ permission, children }: { permission: Permission; children: ReactNode }) {
  const { can, loading } = usePermission();
  if (loading) {
    return <div className="route-loading"><Spin size="large" /></div>;
  }
  if (!can(permission)) {
    return <Navigate to="/403" replace />;
  }
  return children;
}
