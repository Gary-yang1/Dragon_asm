import { ProTable, type ActionType, type ProColumns } from '@ant-design/pro-components';
import { Button, Drawer, Form, Input, Modal, Select, Space, Table, Tag, Tooltip, message } from 'antd';
import { Eye, KeyRound, Pencil, Plus, ShieldCheck, UserCog, UserX } from 'lucide-react';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';

import {
  createPlatformUser,
  listAdminRoles,
  listPlatformUserProjects,
  listPlatformUsers,
  resetPlatformUserCredential,
  transitionPlatformUserStatus,
  updatePlatformUser,
  updatePlatformUserTenantRole,
  type AdminRole,
  type PlatformRole,
  type PlatformUser,
  type PlatformUserInput,
  type PlatformUserProject,
  type PlatformUserStatus
} from '../../api/platform';
import { errorMessage } from '../../api/errorMessage';
import { useAuth } from '../../auth/AuthProvider';
import { Permission, type Role } from '../../auth/permissions';
import { usePermission } from '../../auth/usePermission';
import { PageHeader } from '../../components/PageHeader';
import { StateView } from '../../components/StateView';

type TenantRoleValue = PlatformRole | 'none';

type UserFormValues = {
  username: string;
  name: string;
  email?: string;
  phone?: string;
  department?: string;
  role: TenantRoleValue;
  status: PlatformUserStatus;
  password?: string;
};

type RoleOption = {
  value: TenantRoleValue;
  label: string;
};

const fallbackRoleOptions: RoleOption[] = [
  { value: 'none', label: '无平台角色' },
  { value: 'system_admin', label: '系统管理员' },
  { value: 'security_admin', label: '安全管理员' }
];

const projectRoleLabels: Record<Role, string> = {
  system_admin: '系统管理员',
  security_admin: '安全管理员',
  project_owner: '项目负责人',
  security_ops: '安全运营',
  developer: '整改人员',
  viewer: '只读用户'
};

function parseTenantRoleOption(item: AdminRole): RoleOption | null {
  if (item.scope !== 'tenant' || (item.value !== 'system_admin' && item.value !== 'security_admin')) return null;
  return { value: item.value, label: item.label };
}

function isSelf(currentUsername: string | undefined, currentId: string | undefined, user: PlatformUser) {
  return Boolean((currentUsername && user.username === currentUsername) || (currentId && String(user.id) === currentId));
}

function roleValue(role: PlatformUser['role']): TenantRoleValue {
  return role ?? 'none';
}

function rolePayload(role: TenantRoleValue): PlatformRole | null {
  return role === 'none' ? null : role;
}

export function PlatformUsersPage() {
  const { user } = useAuth();
  const { can } = usePermission();
  const actionRef = useRef<ActionType>(null);
  const [form] = Form.useForm<UserFormValues>();
  const [transitionForm] = Form.useForm<{ reason: string }>();
  const [resetForm] = Form.useForm<{ temporary_password: string; confirmation: string }>();
  const [roleForm] = Form.useForm<{ role: TenantRoleValue }>();
  const [editorVisible, setEditorVisible] = useState(false);
  const [editingUser, setEditingUser] = useState<PlatformUser | null>(null);
  const [transitionUser, setTransitionUser] = useState<PlatformUser | null>(null);
  const [resetUser, setResetUser] = useState<PlatformUser | null>(null);
  const [roleUser, setRoleUser] = useState<PlatformUser | null>(null);
  const [projectsUser, setProjectsUser] = useState<PlatformUser | null>(null);
  const [projects, setProjects] = useState<PlatformUserProject[]>([]);
  const [projectsLoading, setProjectsLoading] = useState(false);
  const [projectsError, setProjectsError] = useState<string | null>(null);
  const [targetStatus, setTargetStatus] = useState<PlatformUserStatus>('disabled');
  const [saving, setSaving] = useState(false);
  const [applyingTransition, setApplyingTransition] = useState(false);
  const [resettingCredential, setResettingCredential] = useState(false);
  const [applyingRole, setApplyingRole] = useState(false);
  const [loadingRoles, setLoadingRoles] = useState(false);
  const [roleOptions, setRoleOptions] = useState<RoleOption[]>(fallbackRoleOptions);
  const [tableError, setTableError] = useState<string | null>(null);

  const canWrite = can(Permission.UserWrite);
  const canResetCredential = can(Permission.UserCredentialReset);
  const canRoleWrite = can(Permission.UserRoleWrite);

  useEffect(() => {
    let active = true;
    setLoadingRoles(true);
    void listAdminRoles()
      .then((roles) => {
        if (!active || !Array.isArray(roles)) return;
        const normalized = roles.map(parseTenantRoleOption).filter((entry): entry is RoleOption => entry !== null);
        setRoleOptions([fallbackRoleOptions[0], ...normalized]);
      })
      .catch(() => {
        if (active) setRoleOptions(fallbackRoleOptions);
      })
      .finally(() => {
        if (active) setLoadingRoles(false);
      });
    return () => {
      active = false;
    };
  }, []);

  const resetEditor = useCallback(() => {
    form.resetFields();
    setEditingUser(null);
  }, [form]);

  const openCreate = useCallback(() => {
    resetEditor();
    form.setFieldsValue({ role: 'none', status: 'active' });
    setEditorVisible(true);
  }, [form, resetEditor]);

  const openEdit = useCallback(
    (target: PlatformUser) => {
      setEditingUser(target);
      form.setFieldsValue({
        username: target.username,
        name: target.name,
        email: target.email,
        phone: target.phone ?? '',
        department: target.department ?? '',
        role: roleValue(target.role),
        status: target.status
      });
      setEditorVisible(true);
    },
    [form]
  );

  const openTransition = useCallback(
    (target: PlatformUser) => {
      setTargetStatus(target.status === 'active' ? 'disabled' : 'active');
      setTransitionUser(target);
      transitionForm.resetFields();
    },
    [transitionForm]
  );

  const onTransitionSubmit = useCallback(async () => {
    if (!transitionUser) return;
    const values = await transitionForm.validateFields();
    setApplyingTransition(true);
    try {
      await transitionPlatformUserStatus(transitionUser.id, {
        status: targetStatus,
        reason: values.reason.trim()
      });
      message.success(targetStatus === 'active' ? '用户已启用' : '用户已停用，现有会话已失效');
      setTransitionUser(null);
      transitionForm.resetFields();
      actionRef.current?.reload();
    } catch (error) {
      message.error(errorMessage(error));
    } finally {
      setApplyingTransition(false);
    }
  }, [targetStatus, transitionForm, transitionUser]);

  const submitUser = useCallback(async () => {
    const values = await form.validateFields();
    setSaving(true);
    try {
      if (editingUser) {
        await updatePlatformUser(editingUser.id, {
          name: values.name,
          email: values.email?.trim() ?? '',
          phone: values.phone?.trim() ?? '',
          department: values.department?.trim() ?? ''
        });
        message.success('用户资料已更新');
      } else {
        const input: PlatformUserInput = {
          username: values.username,
          name: values.name,
          email: values.email?.trim() ?? '',
          phone: values.phone?.trim() ?? '',
          department: values.department?.trim() ?? '',
          role: rolePayload(values.role),
          status: values.status,
          password: values.password ?? ''
        };
        await createPlatformUser(input);
        message.success('用户已创建');
      }
      setEditorVisible(false);
      resetEditor();
      actionRef.current?.reload();
    } catch (error) {
      message.error(errorMessage(error));
    } finally {
      setSaving(false);
    }
  }, [editingUser, form, resetEditor]);

  const openRoleEditor = useCallback((target: PlatformUser) => {
    setRoleUser(target);
    roleForm.setFieldsValue({ role: roleValue(target.role) });
  }, [roleForm]);

  const onRoleSubmit = useCallback(async () => {
    if (!roleUser) return;
    const values = await roleForm.validateFields();
    setApplyingRole(true);
    try {
      await updatePlatformUserTenantRole(roleUser.id, { role: rolePayload(values.role) });
      message.success('平台角色已更新，用户现有会话已失效');
      setRoleUser(null);
      roleForm.resetFields();
      actionRef.current?.reload();
    } catch (error) {
      message.error(errorMessage(error));
    } finally {
      setApplyingRole(false);
    }
  }, [roleForm, roleUser]);

  const openResetCredential = useCallback(
    (target: PlatformUser) => {
      resetForm.resetFields();
      setResetUser(target);
    },
    [resetForm]
  );

  const onResetCredential = useCallback(async () => {
    if (!resetUser) return;
    const values = await resetForm.validateFields();
    setResettingCredential(true);
    try {
      await resetPlatformUserCredential(resetUser.id, values.temporary_password);
      message.success('临时密码已设置，用户现有会话已失效');
      setResetUser(null);
      resetForm.resetFields();
      actionRef.current?.reload();
    } catch (error) {
      message.error(errorMessage(error));
    } finally {
      setResettingCredential(false);
    }
  }, [resetForm, resetUser]);

  const loadProjects = useCallback(async (target: PlatformUser) => {
    setProjectsUser(target);
    setProjectsLoading(true);
    setProjectsError(null);
    try {
      const response = await listPlatformUserProjects(target.id);
      setProjects(response.items);
    } catch (error) {
      setProjects([]);
      setProjectsError(errorMessage(error));
    } finally {
      setProjectsLoading(false);
    }
  }, []);

  const roleValueEnum = useMemo(
    () => Object.fromEntries(roleOptions.map((item) => [item.value, item.label])),
    [roleOptions]
  );

  const userColumns = useMemo<ProColumns<PlatformUser>[]>(
    () => [
      { title: '搜索', dataIndex: 'q', hideInTable: true, fieldProps: { placeholder: '用户名 / 姓名 / 联系方式 / 部门' } },
      { title: '用户名', dataIndex: 'username', copyable: true, search: false },
      { title: '姓名', dataIndex: 'name', search: false },
      { title: '邮箱', dataIndex: 'email', copyable: true, search: false, responsive: ['lg'] },
      { title: '手机号', dataIndex: 'phone', search: false, responsive: ['xl'] },
      { title: '部门', dataIndex: 'department', search: false, responsive: ['md'] },
      {
        title: '平台角色',
        dataIndex: 'role',
        valueType: 'select',
        responsive: ['sm'],
        valueEnum: roleValueEnum,
        render: (_, row) => (row.role ? <Tag color="blue">{roleValueEnum[row.role] ?? row.role}</Tag> : <Tag>无</Tag>)
      },
      { title: '项目数', dataIndex: 'project_count', search: false, width: 80, responsive: ['md'] },
      {
        title: '状态',
        dataIndex: 'status',
        valueType: 'select',
        valueEnum: { active: '启用', disabled: '停用' },
        render: (_, row) => <Tag color={row.status === 'active' ? 'green' : 'default'}>{row.status === 'active' ? '启用' : '停用'}</Tag>
      },
      { title: '最近登录', dataIndex: 'last_login_at', valueType: 'dateTime', search: false, responsive: ['xl'] },
      { title: '更新时间', dataIndex: 'updated_at', valueType: 'dateTime', search: false, responsive: ['xl'] },
      {
        title: '操作',
        valueType: 'option',
        width: 330,
        render: (_, row) => (
          <Space size={2} wrap>
            <Button type="link" icon={<Eye size={14} />} onClick={() => void loadProjects(row)}>
              项目授权
            </Button>
            {canWrite ? (
              <Button type="link" icon={<Pencil size={14} />} onClick={() => openEdit(row)} aria-label={`编辑${row.username}`}>
                编辑
              </Button>
            ) : null}
            {canRoleWrite ? (
              <Button type="link" icon={<UserCog size={14} />} onClick={() => openRoleEditor(row)} aria-label={`设置${row.username}平台角色`}>
                平台角色
              </Button>
            ) : null}
            {canWrite ? (
              <Tooltip title={isSelf(user?.username, user?.id, row) ? '不能停用当前账号' : undefined}>
                <Button
                  type="link"
                  danger={row.status === 'active'}
                  icon={row.status === 'active' ? <UserX size={14} /> : <ShieldCheck size={14} />}
                  disabled={row.status === 'active' && isSelf(user?.username, user?.id, row)}
                  onClick={() => openTransition(row)}
                >
                  {row.status === 'active' ? '停用' : '启用'}
                </Button>
              </Tooltip>
            ) : null}
            {canResetCredential ? (
              <Button type="link" icon={<KeyRound size={14} />} onClick={() => openResetCredential(row)}>
                重置密码
              </Button>
            ) : null}
          </Space>
        )
      }
    ],
    [canResetCredential, canRoleWrite, canWrite, loadProjects, openEdit, openResetCredential, openRoleEditor, openTransition, roleValueEnum, user?.id, user?.username]
  );

  return (
    <section className="page-surface">
      <PageHeader
        title="平台用户管理"
        subtitle="管理租户内账号生命周期与平台角色；项目成员角色在项目工作区维护"
        actions={
          canWrite ? (
            <Button type="primary" icon={<Plus size={16} />} onClick={openCreate} loading={loadingRoles}>
              新建用户
            </Button>
          ) : null
        }
      />
      <StateView error={tableError} onRetry={() => { setTableError(null); actionRef.current?.reload(); }}>
        <ProTable<PlatformUser>
          rowKey="id"
          actionRef={actionRef}
          columns={userColumns}
          toolBarRender={false}
          search={{ labelWidth: 90 }}
          request={async (params) => {
            try {
              const page = await listPlatformUsers(params.current ?? 1, params.pageSize ?? 20, {
                q: typeof params.q === 'string' ? params.q.trim() : undefined,
                status: params.status as PlatformUserStatus | undefined,
                role: params.role as PlatformRole | 'none' | undefined
              });
              setTableError(null);
              return { data: page.items, total: page.total, success: true };
            } catch (error) {
              setTableError(errorMessage(error));
              return { data: [], total: 0, success: false };
            }
          }}
          pagination={{ pageSize: 20, showSizeChanger: true }}
          locale={{ emptyText: '暂无平台用户' }}
          rowSelection={false}
          scroll={{ x: 1180 }}
        />
      </StateView>

      <Drawer
        title={editingUser ? '编辑用户' : '新建用户'}
        width={520}
        open={editorVisible}
        destroyOnClose
        onClose={() => { setEditorVisible(false); resetEditor(); }}
        extra={
          <Space>
            <Button onClick={() => { setEditorVisible(false); resetEditor(); }}>取消</Button>
            <Button type="primary" loading={saving} onClick={() => void submitUser()}>
              {editingUser ? '保存' : '创建'}
            </Button>
          </Space>
        }
      >
        <Form form={form} layout="vertical">
          <Form.Item
            name="username"
            label="用户名"
            rules={[{ required: true, max: 128, pattern: /^[A-Za-z0-9][A-Za-z0-9._-]*$/, message: '仅支持 ASCII 字母、数字、点、下划线和短横线' }]}
          >
            <Input disabled={Boolean(editingUser)} placeholder="创建后不可修改，保存时统一转为小写" />
          </Form.Item>
          <Form.Item name="name" label="姓名" rules={[{ required: true, max: 255 }]}>
            <Input />
          </Form.Item>
          <Form.Item name="email" label="邮箱" rules={[{ type: 'email', max: 255 }]}>
            <Input />
          </Form.Item>
          <Form.Item name="phone" label="手机号" rules={[{ max: 32 }]}>
            <Input />
          </Form.Item>
          <Form.Item name="department" label="部门" rules={[{ max: 128 }]}>
            <Input />
          </Form.Item>
          {!editingUser ? (
            <>
              <Form.Item name="role" label="平台角色" rules={[{ required: true }]}>
                <Select options={roleOptions} disabled={!canRoleWrite} />
              </Form.Item>
              <Form.Item name="status" label="状态" rules={[{ required: true }]}>
                <Select options={[{ value: 'active', label: '启用' }, { value: 'disabled', label: '停用' }]} />
              </Form.Item>
              <Form.Item name="password" label="临时密码" rules={[{ required: true, min: 12, max: 72 }]}>
                <Input.Password autoComplete="new-password" placeholder="12–72 字节，服务端仅保存 bcrypt 哈希" />
              </Form.Item>
            </>
          ) : null}
        </Form>
      </Drawer>

      <Modal
        title="设置平台角色"
        open={Boolean(roleUser)}
        okText="保存角色"
        okButtonProps={{ loading: applyingRole }}
        onOk={() => void onRoleSubmit()}
        onCancel={() => { setRoleUser(null); roleForm.resetFields(); }}
      >
        <Form form={roleForm} layout="vertical">
          <Form.Item name="role" label={roleUser?.username ?? '平台角色'} rules={[{ required: true }]}>
            <Select options={roleOptions} loading={loadingRoles} />
          </Form.Item>
        </Form>
      </Modal>

      <Modal
        title={targetStatus === 'active' ? '启用用户' : '停用用户'}
        open={Boolean(transitionUser)}
        okText="确认"
        okButtonProps={{ loading: applyingTransition, danger: targetStatus === 'disabled' }}
        onOk={() => void onTransitionSubmit()}
        onCancel={() => { setTransitionUser(null); transitionForm.resetFields(); }}
      >
        <p>即将{targetStatus === 'active' ? '启用' : '停用'}用户 <strong>{transitionUser?.username}</strong>。</p>
        {targetStatus === 'disabled' ? <p>停用后，该用户现有 access/refresh token 将立即失效。</p> : null}
        <Form form={transitionForm} layout="vertical">
          <Form.Item name="reason" label="变更原因" rules={[{ required: true, max: 512 }]}>
            <Input.TextArea autoSize={{ minRows: 3, maxRows: 6 }} />
          </Form.Item>
        </Form>
      </Modal>

      <Modal
        title="重置临时密码"
        open={Boolean(resetUser)}
        okText="确认重置"
        okButtonProps={{ loading: resettingCredential }}
        onOk={() => void onResetCredential()}
        onCancel={() => { setResetUser(null); resetForm.resetFields(); }}
      >
        <p>为用户 <strong>{resetUser?.username}</strong> 设置临时密码。提交后不会回显，现有会话立即失效。</p>
        <Form form={resetForm} layout="vertical">
          <Form.Item name="temporary_password" label="临时密码" rules={[{ required: true, min: 12, max: 72 }]}>
            <Input.Password autoComplete="new-password" />
          </Form.Item>
          <Form.Item
            name="confirmation"
            label="确认临时密码"
            dependencies={['temporary_password']}
            rules={[
              { required: true },
              ({ getFieldValue }) => ({
                validator: (_, value) => value === getFieldValue('temporary_password') ? Promise.resolve() : Promise.reject(new Error('两次输入的密码不一致'))
              })
            ]}
          >
            <Input.Password autoComplete="new-password" />
          </Form.Item>
        </Form>
      </Modal>

      <Modal
        title={`${projectsUser?.username ?? ''} 的项目授权`}
        open={Boolean(projectsUser)}
        footer={<Button onClick={() => setProjectsUser(null)}>关闭</Button>}
        onCancel={() => setProjectsUser(null)}
        width={720}
      >
        <StateView
          loading={projectsLoading}
          error={projectsError}
          empty={!projectsLoading && !projectsError && projects.length === 0}
          emptyText="该用户尚未加入项目"
          onRetry={projectsUser ? () => void loadProjects(projectsUser) : undefined}
        >
          <Table<PlatformUserProject>
            rowKey="id"
            size="small"
            pagination={false}
            scroll={{ x: 620 }}
            dataSource={projects}
            columns={[
              { title: '项目编码', dataIndex: 'project_code' },
              { title: '项目名称', dataIndex: 'name' },
              { title: '项目角色', dataIndex: 'role', render: (value: Role) => projectRoleLabels[value] ?? value },
              { title: '项目状态', dataIndex: 'status' }
            ]}
          />
        </StateView>
      </Modal>
    </section>
  );
}
