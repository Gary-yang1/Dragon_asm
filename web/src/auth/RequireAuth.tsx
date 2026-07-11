import { Navigate, useLocation } from 'react-router-dom';
import type { ReactNode } from 'react';
import { Spin } from 'antd';

import { useAuth } from './AuthProvider';

export function RequireAuth({ children }: { children: ReactNode }) {
  const { accessToken, ready, user } = useAuth();
  const location = useLocation();
  if (!accessToken) {
    return <Navigate to="/login" replace state={{ from: location }} />;
  }
  if (!ready) {
    return <div className="route-loading"><Spin size="large" /></div>;
  }
  if (user?.mustChangePassword && location.pathname !== '/change-password') {
    return <Navigate to="/change-password" replace />;
  }
  return children;
}
