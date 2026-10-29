import { Alert, Button, Descriptions, Form, Input, Select, Space, Switch, Table, Tabs, Tag, Typography, message } from 'antd';
import { CheckCircle2, CircleAlert, Play } from 'lucide-react';
import { useCallback, useEffect, useRef, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';

import {
  createICPFiling,
  createProjectDomain,
  createProjectSubject,
  getOnboardingStatus,
  getProject,
  listICPFilings,
  listProjectDomains,
  listProjectSubjects,
  transitionProject,
  updateProject,
  type ICPFiling,
  type OnboardingStatus,
  type Project,
  type ProjectDomain,
  type ProjectSubject
} from '../../api/projects';
import { errorMessage } from '../../api/errorMessage';
import { listPlatformUsers } from '../../api/platform';
import { useAuth } from '../../auth/AuthProvider';
import { Permission } from '../../auth/permissions';
import { usePermission } from '../../auth/usePermission';
import { PageHeader } from '../../components/PageHeader';
import { describe, projectStatusMeta } from '../../utils/taxonomy';
import { StateView } from '../../components/StateView';
import { useProjectId, useProjectWorkspace } from '../../projects/ProjectContext';

const profileLabels: Record<string, string> = { company: '企业', government: '政府机构', institution: '事业单位', individual: '个人', other: '其他', unverified: '待核验', verified: '已核验', mismatch: '不匹配', valid: '有效', invalid: '无效', cancelled: '已取消' };
function profileLabel(value: string) { return profileLabels[value] ?? value; }

export function ProjectProfilePage() {
  const projectId = useProjectId();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { refresh: refreshWorkspace } = useProjectWorkspace();
  const { can } = usePermission();
  const { can: canGlobal } = useAuth();
  const canListOwners = canGlobal(Permission.UserRead);
  const [ownerQuery, setOwnerQuery] = useState('');
  const [ownerChoices, setOwnerChoices] = useState<Array<{ value: string; label: string }>>([]);
  const [ownersLoading, setOwnersLoading] = useState(false);
  const [ownerError, setOwnerError] = useState('');
  const [project, setProject] = useState<Project | null>(null);
  const [onboarding, setOnboarding] = useState<OnboardingStatus | null>(null);
  const [subjects, setSubjects] = useState<ProjectSubject[]>([]);
  const [domains, setDomains] = useState<ProjectDomain[]>([]);
  const [filings, setFilings] = useState<ICPFiling[]>([]);
  const [saving, setSaving] = useState(false);
  const saveInFlight = useRef(false);
  const [formError, setFormError] = useState('');
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState('');
  const [basicForm] = Form.useForm();
  const [subjectForm] = Form.useForm();
  const [domainForm] = Form.useForm();
  const [icpForm] = Form.useForm();
  const activationRef = useRef<HTMLDivElement | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setLoadError('');
    try {
      const [projectData, status, subjectData, domainData, filingData] = await Promise.all([
        getProject(projectId), getOnboardingStatus(projectId), listProjectSubjects(projectId),
        listProjectDomains(projectId), listICPFilings(projectId)
      ]);
      setProject(projectData);
      setOnboarding(status);
      setSubjects(subjectData.items);
      setDomains(domainData.items);
      setFilings(filingData.items);
      basicForm.setFieldsValue(projectData);
    } catch (error) {
      setLoadError(errorMessage(error));
    } finally {
      setLoading(false);
    }
  }, [basicForm, projectId]);

  useEffect(() => { void load(); }, [load]);

  useEffect(() => {
    if (!canListOwners) return;
    let active = true;
    const timer = globalThis.setTimeout(() => {
      setOwnersLoading(true);
      setOwnerError('');
      void listPlatformUsers(1, 50, { q: ownerQuery }).then((page) => {
        if (active) setOwnerChoices(page.items.map((owner) => ({ value: String(owner.id), label: `${owner.name || owner.username}（${owner.username}）` })));
      }).catch(() => { if (active) setOwnerError('无法加载负责人，请重新输入姓名搜索。'); })
        .finally(() => { if (active) setOwnersLoading(false); });
    }, 250);
    return () => { active = false; globalThis.clearTimeout(timer); };
  }, [canListOwners, ownerQuery]);

  const reloadWorkspace = useCallback(async () => {
    await Promise.all([load(), refreshWorkspace()]);
  }, [load, refreshWorkspace]);

  useEffect(() => {
    if (searchParams.get('focus') !== 'activation' || loading || !project) return;
    const frame = globalThis.requestAnimationFrame(() => {
      activationRef.current?.scrollIntoView?.({ behavior: 'smooth', block: 'center' });
      activationRef.current?.focus({ preventScroll: true });
    });
    return () => globalThis.cancelAnimationFrame(frame);
  }, [loading, project, searchParams]);

  async function saveAction(action: () => Promise<void>) {
    if (saveInFlight.current) return;
    saveInFlight.current = true;
    setSaving(true);
    setFormError('');
    try { await action(); }
    catch (error) {
      if (!(typeof error === 'object' && error !== null && 'errorFields' in error)) setFormError(errorMessage(error));
    } finally { saveInFlight.current = false; setSaving(false); }
  }

  async function saveBasic() {
    await updateProject(projectId, await basicForm.validateFields());
    message.success('项目基础信息已保存');
    await reloadWorkspace();
  }

  async function addSubject() {
    const values = await subjectForm.validateFields();
    await createProjectSubject(projectId, { ...values, verification_status: 'unverified', source: 'manual', evidence_summary: '' });
    subjectForm.resetFields();
    message.success('主体已添加');
    await reloadWorkspace();
  }

  async function addDomain() {
    const values = await domainForm.validateFields();
    await createProjectDomain(projectId, { ...values, ownership_status: 'unverified', source: 'manual', evidence_summary: '' });
    domainForm.resetFields();
    message.success('主域名已添加');
    await reloadWorkspace();
  }

  async function addICP() {
    const values = await icpForm.validateFields();
    await createICPFiling(projectId, { ...values, filing_type: 'filing', status: 'unverified', source: 'manual', evidence_summary: '' });
    icpForm.resetFields();
    message.success('ICP 备案已添加');
    await reloadWorkspace();
  }

  async function activate() {
    try {
      await transitionProject(projectId, 'active');
      message.success(project?.status === 'suspended' ? '项目已恢复' : '项目已激活');
      await reloadWorkspace();
      globalThis.dispatchEvent(new Event('asm:projects-changed'));
      const requestedReturnTo = searchParams.get('returnTo');
      const projectPrefix = `/projects/${projectId}/`;
      if (requestedReturnTo?.startsWith(projectPrefix)) {
        navigate(requestedReturnTo, { replace: true });
      }
    } catch (error) {
      message.error(errorMessage(error));
    }
  }

  return (
    <section className="page-surface">
      <StateView loading={loading} error={loadError} empty={!project} onRetry={() => void load()}>
        {project ? <>
          <PageHeader
            title={project.name}
            subtitle={`${project.project_code} · 项目资料与启用条件`}
            summary={<Space wrap>
              <Tag>{describe(projectStatusMeta, project.status).label}</Tag>
              {(project.status === 'draft' || project.status === 'suspended') && onboarding?.ready_to_activate
                ? <Tag color="green" icon={<CheckCircle2 size={13} />}>{project.status === 'suspended' ? '可恢复' : '可激活'}</Tag>
                : null}
              {(project.status === 'draft' || project.status === 'suspended') && onboarding && !onboarding.ready_to_activate
                ? <Tag color="gold" icon={<CircleAlert size={13} />}>资料待完善</Tag>
                : null}
            </Space>}
          />
          <div id="project-activation-panel" ref={activationRef} tabIndex={-1} className="project-activation-panel">
            {project.status === 'archived' ? (
              <Alert type="info" showIcon message="项目已归档" description="归档项目不能重新激活，也不能启动新的发现任务。" />
            ) : null}
            {(project.status === 'draft' || project.status === 'suspended') && onboarding && !onboarding.ready_to_activate ? (
              <Alert
                type="warning"
                showIcon
                message={project.status === 'suspended' ? '项目尚未满足恢复条件' : '项目尚未满足激活条件'}
                description={`待完成：${onboarding.missing.join('、')}`}
                action={onboarding.missing.includes('valid_scope') && can(Permission.DiscoveryRead)
                  ? <Button onClick={() => navigate(`/projects/${projectId}/discovery`)}>配置授权范围</Button>
                  : undefined}
              />
            ) : null}
            {(project.status === 'draft' || project.status === 'suspended') && onboarding?.ready_to_activate && can(Permission.ProjectWrite) ? (
              <div className="project-activate-bar">
                <Typography.Text>{project.status === 'suspended' ? '项目已满足恢复条件。' : '项目资料和授权范围已满足激活条件。'}</Typography.Text>
                <Button type="primary" icon={<Play size={15} />} onClick={() => void activate()}>
                  {project.status === 'suspended' ? '恢复项目' : '激活项目'}
                </Button>
              </div>
            ) : null}
            {(project.status === 'draft' || project.status === 'suspended') && onboarding?.ready_to_activate && !can(Permission.ProjectWrite) ? (
              <Alert type="info" showIcon message="项目已满足启用条件" description="请联系项目负责人或管理员完成激活。" />
            ) : null}
          </div>
          {formError && <Alert type="error" showIcon message={formError} />}
          <Tabs items={[
            {
              key: 'basic', label: '基础信息', children: <>
                <Descriptions size="small" column={{ xs: 1, md: 2 }} className="project-profile-summary">

                  <Descriptions.Item label="主主体">{subjects.find((item) => item.is_primary)?.subject_name ?? '-'}</Descriptions.Item><Descriptions.Item label="主域名">{domains.find((item) => item.is_primary)?.domain ?? '-'}</Descriptions.Item>
                </Descriptions>
                <Form form={basicForm} disabled={saving || !can(Permission.ProjectWrite)} layout="vertical" className="project-profile-form record-form">
                  <Form.Item name="name" label="项目名称" rules={[{ required: true, max: 255 }]}><Input /></Form.Item>
                  <Form.Item name="owner_user_id" label={canListOwners ? '项目负责人' : '负责人用户编号'} rules={[{ required: true }]} extra={ownerError || undefined}>
                    {canListOwners ? <Select showSearch filterOption={false} onSearch={setOwnerQuery} loading={ownersLoading} placeholder="搜索姓名或账号" options={ownerChoices.some((choice) => choice.value === project.owner_user_id) ? ownerChoices : [{ value: project.owner_user_id, label: `用户 #${project.owner_user_id}` }, ...ownerChoices]} /> : <Input />}
                  </Form.Item>
                  <Form.Item name="business_unit" label="业务单元"><Input maxLength={128} /></Form.Item>
                  <Form.Item name="criticality" label="重要性"><Select options={Object.entries({ low: '低', medium: '中', high: '高', critical: '关键' }).map(([value, label]) => ({ value, label }))} /></Form.Item>
                  <Form.Item name="description" label="说明" className="form-full-row"><Input.TextArea rows={3} /></Form.Item>
                  {can(Permission.ProjectWrite) ? <Button type="primary" loading={saving} onClick={() => void saveAction(saveBasic)}>保存基础信息</Button> : null}
                </Form>
              </>
            },
            {
              key: 'subjects', label: `主体 (${subjects.length})`, children: <Space direction="vertical" className="full-width" size={16}>
                <Table rowKey="id" pagination={false} dataSource={subjects} columns={[{ title: '单位名称', dataIndex: 'subject_name' }, { title: '类型', dataIndex: 'subject_type', render: (value: string) => profileLabel(value) }, { title: '登记代码', dataIndex: 'registration_code' }, { title: '主主体', dataIndex: 'is_primary', render: (value) => value ? <Tag color="blue">是</Tag> : '-' }, { title: '核验', dataIndex: 'verification_status', render: (value: string) => profileLabel(value) }]} />
                {can(Permission.ProjectWrite) ? <details className="inline-disclosure"><summary>添加主体</summary><Form disabled={saving} form={subjectForm} layout="vertical" className="record-form" initialValues={{ subject_type: 'company', country_code: 'CN', is_primary: subjects.length === 0 }}><Form.Item label="单位名称" name="subject_name" rules={[{ required: true }]}><Input placeholder="单位名称" /></Form.Item><Form.Item label="主体类型" name="subject_type"><Select style={{ width: 130 }} options={Object.entries({ company: '企业', government: '政府机构', institution: '事业单位', individual: '个人', other: '其他' }).map(([value, label]) => ({ value, label }))} /></Form.Item><Form.Item label="登记代码" name="registration_code"><Input placeholder="统一社会信用代码" /></Form.Item><Form.Item label="国家/地区代码" name="country_code"><Input style={{ width: 72 }} /></Form.Item><Form.Item label="地区" name="region"><Input placeholder="地区" /></Form.Item><Form.Item label="设为主要项" name="is_primary" valuePropName="checked"><Switch checkedChildren="主" /></Form.Item><Button type="primary" loading={saving} onClick={() => void saveAction(addSubject)}>添加主体</Button></Form></details> : null}
              </Space>
            },
            {
              key: 'domains', label: `主域名 (${domains.length})`, children: <Space direction="vertical" className="full-width" size={16}>
                <Table rowKey="id" pagination={false} dataSource={domains} columns={[{ title: '域名', dataIndex: 'domain' }, { title: '主体', dataIndex: 'subject_id', render: (id) => subjects.find((item) => item.id === id)?.subject_name ?? '-' }, { title: '主域名', dataIndex: 'is_primary', render: (value) => value ? <Tag color="blue">是</Tag> : '-' }, { title: '归属核验', dataIndex: 'ownership_status', render: (value: string) => profileLabel(value) }]} />
                {can(Permission.ProjectWrite) ? <details className="inline-disclosure"><summary>添加主域名</summary><Form disabled={saving} form={domainForm} layout="vertical" className="record-form" initialValues={{ is_primary: domains.length === 0 }}><Form.Item label="主域名" name="domain" rules={[{ required: true }]}><Input placeholder="example.com" /></Form.Item><Form.Item label="关联主体" name="subject_id"><Select style={{ width: 200 }} placeholder="关联主体" options={subjects.map((item) => ({ value: item.id, label: item.subject_name }))} /></Form.Item><Form.Item label="设为主要项" name="is_primary" valuePropName="checked"><Switch checkedChildren="主" /></Form.Item><Button type="primary" loading={saving} onClick={() => void saveAction(addDomain)}>添加主域名</Button></Form></details> : null}
              </Space>
            },
            {
              key: 'icp', label: `ICP 备案 (${filings.length})`, children: <Space direction="vertical" className="full-width" size={16}>
                <Alert type="info" showIcon message="ICP 仅作为业务画像，不代表扫描授权。" />
                <Table rowKey="id" pagination={false} dataSource={filings} columns={[{ title: '备案号', dataIndex: 'filing_no' }, { title: '网站名称', dataIndex: 'website_name' }, { title: '主体', dataIndex: 'subject_id', render: (id) => subjects.find((item) => item.id === id)?.subject_name ?? '-' }, { title: '状态', dataIndex: 'status', render: (value: string) => profileLabel(value) }]} />
                {can(Permission.ProjectWrite) ? <details className="inline-disclosure"><summary>添加备案</summary><Form disabled={saving} form={icpForm} layout="vertical" className="record-form"><Form.Item label="ICP备案号" name="filing_no" rules={[{ required: true }]}><Input placeholder="ICP备案号" /></Form.Item><Form.Item label="网站名称" name="website_name"><Input placeholder="网站名称" /></Form.Item><Form.Item label="关联主体" name="subject_id" rules={[{ required: true }]}><Select style={{ width: 200 }} placeholder="备案主体" options={subjects.map((item) => ({ value: item.id, label: item.subject_name }))} /></Form.Item><Form.Item label="关联主域名" name="domain_profile_ids"><Select mode="multiple" style={{ minWidth: 220 }} placeholder="关联主域名" options={domains.map((item) => ({ value: item.id, label: item.domain }))} /></Form.Item><Button type="primary" loading={saving} onClick={() => void saveAction(addICP)}>添加备案</Button></Form></details> : null}
              </Space>
            }
          ]} />
        </> : null}
      </StateView>
    </section>
  );
}
