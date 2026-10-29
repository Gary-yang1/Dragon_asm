import { Navigate } from 'react-router-dom';
import { Alert, Button, Spin } from 'antd';
import type { ReactNode } from 'react';

import { Permission } from './permissions';
import { usePermission } from './usePermission';

export function RequirePermission({ permission, children }: { permission: Permission; children: ReactNode }) {
  const { can, loading, error, retry } = usePermission();

  if (loading) {
    return <div className="route-loading"><Spin size="large" /></div>;
  }

  // A failed capability fetch is not a denial. Redirecting to the terminal /403
  // page told an authorized operator they lacked permission whenever the request
  // timed out, with no way to recover.
  if (error) {
    return (
      <div className="route-error">
        <Alert
          type="error"
          showIcon
          message="项目权限加载失败"
          description={error}
          action={retry ? <Button onClick={() => void retry()}>重试</Button> : undefined}
        />
      </div>
    );
  }

  if (!can(permission)) {
    return <Navigate to="/403" replace />;
  }

  return children;
}
