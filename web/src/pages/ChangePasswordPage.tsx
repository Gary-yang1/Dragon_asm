import { Alert, Button, Form, Input, Typography, message } from 'antd';
import { KeyRound, Lock, ShieldCheck } from 'lucide-react';
import { useState } from 'react';
import { useNavigate } from 'react-router-dom';

import { errorMessage } from '../api/errorMessage';
import { useAuth } from '../auth/AuthProvider';

type PasswordForm = {
  currentPassword: string;
  newPassword: string;
  confirmation: string;
};

export function ChangePasswordPage() {
  const { changePassword, loading } = useAuth();
  const navigate = useNavigate();
  const [error, setError] = useState('');

  async function onFinish(values: PasswordForm) {
    setError('');
    try {
      await changePassword(values.currentPassword, values.newPassword);
      message.success('密码已更新，请重新登录');
      navigate('/login', { replace: true });
    } catch (cause) {
      setError(errorMessage(cause));
    }
  }

  return (
    <main className="login-shell">
      <div className="login-logo">
        <span className="layout-brand-mark">A</span>
        <div><strong>ArgusASM</strong><span>攻击面梳理平台</span></div>
      </div>
      <section className="login-shell-grid">
        <section className="login-panel">
          <div className="login-panel-head">
            <span className="login-panel-icon" aria-hidden="true"><ShieldCheck size={18} /></span>
            <div><Typography.Title level={1}>修改初始密码</Typography.Title></div>
          </div>
          <Form<PasswordForm> layout="vertical" onFinish={onFinish} requiredMark={false}>
            {error ? <Alert type="error" message={error} showIcon /> : null}
            <Form.Item name="currentPassword" label="当前密码" rules={[{ required: true, max: 72 }]}>
              <Input.Password prefix={<Lock size={16} />} autoComplete="current-password" />
            </Form.Item>
            <Form.Item name="newPassword" label="新密码" rules={[{ required: true, min: 12, max: 72 }]}>
              <Input.Password prefix={<KeyRound size={16} />} autoComplete="new-password" />
            </Form.Item>
            <Form.Item
              name="confirmation"
              label="确认新密码"
              dependencies={['newPassword']}
              rules={[
                { required: true },
                ({ getFieldValue }) => ({
                  validator: (_, value) => value === getFieldValue('newPassword')
                    ? Promise.resolve()
                    : Promise.reject(new Error('两次输入的密码不一致'))
                })
              ]}
            >
              <Input.Password prefix={<KeyRound size={16} />} autoComplete="new-password" />
            </Form.Item>
            <Button aria-label="确认修改密码" type="primary" htmlType="submit" loading={loading} block>
              确认修改
            </Button>
          </Form>
        </section>
      </section>
    </main>
  );
}
