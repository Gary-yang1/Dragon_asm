import { Button, Empty, Result, Skeleton } from 'antd';
import type { ReactNode } from 'react';

type StateViewProps = {
  loading?: boolean;
  error?: string | null;
  empty?: boolean;
  emptyText?: ReactNode;
  permissionDenied?: boolean;
  onRetry?: () => void;
  children: ReactNode;
};

export function StateView({ loading, error, empty, emptyText, permissionDenied, onRetry, children }: StateViewProps) {
  if (loading) return <Skeleton active paragraph={{ rows: 6 }} />;
  if (permissionDenied) return <Result status="403" title="403" subTitle="无权限访问" />;
  if (error) {
    return <Result status="error" title="加载失败" subTitle={error} extra={onRetry ? <Button onClick={onRetry}>重试</Button> : null} />;
  }
  if (empty) return <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={emptyText} />;
  return children;
}
