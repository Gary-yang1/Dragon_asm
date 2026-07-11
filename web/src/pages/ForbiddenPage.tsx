import { Result } from 'antd';

export function ForbiddenPage() {
  return <Result status="403" title="403" subTitle="无权限访问" />;
}
