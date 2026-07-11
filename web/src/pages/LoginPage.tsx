import { Alert, Button, Form, Input, Typography } from 'antd';
import { Lock, ShieldCheck, UserRound } from 'lucide-react';
import { useState } from 'react';
import { Navigate, useLocation, useNavigate } from 'react-router-dom';

import { useAuth } from '../auth/AuthProvider';

type LoginForm = {
  username: string;
  password: string;
};

export function LoginPage() {
  const { accessToken, login, loading } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [error, setError] = useState('');
  const from = (location.state as { from?: { pathname?: string } } | null)?.from?.pathname ?? '/';

  if (accessToken) return <Navigate to="/" replace />;

  async function onFinish(values: LoginForm) {
    setError('');
    try {
      const authenticatedUser = await login(values.username, values.password);
      navigate(authenticatedUser.mustChangePassword ? '/change-password' : from, { replace: true });
    } catch (err) {
      setError(err instanceof Error ? err.message : '登录失败');
    }
  }

  return (
    <main className="login-shell">
      <div className="login-logo">
        <img src="/asmlogo.png" alt="BiuASM Logo" className="logo-img" />
        <div>
          <strong>BiuASM</strong>
          <span>攻击面梳理平台</span>
        </div>
      </div>
      <section className="login-shell-grid">
        <section className="login-panel">
          <div className="login-panel-head">
            <span className="login-panel-icon" aria-hidden="true">
              <ShieldCheck size={18} />
            </span>
            <div>
              <Typography.Title level={1}>欢迎使用</Typography.Title>
              <Typography.Text type="secondary">登录后进入暴露面风险工作台</Typography.Text>
            </div>
          </div>
          <Form<LoginForm> layout="vertical" onFinish={onFinish} requiredMark={false}>
            {error ? <Alert type="error" message={error} showIcon /> : null}
            <Form.Item name="username" label="账号" rules={[{ required: true, message: '请输入账号' }]}>
              <Input prefix={<UserRound size={16} />} autoComplete="username" />
            </Form.Item>
            <Form.Item name="password" label="密码" rules={[{ required: true, message: '请输入密码' }]}>
              <Input.Password prefix={<Lock size={16} />} autoComplete="current-password" />
            </Form.Item>
            <Button aria-label="登录" type="primary" htmlType="submit" loading={loading} block>
              登录
            </Button>
          </Form>
        </section>
      </section>
    </main>
  );
}
