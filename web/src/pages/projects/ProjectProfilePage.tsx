import { Alert, Button, Descriptions, Form, Input, Select, Space, Switch, Table, Tabs, Tag, Typography, message } from 'antd';
import { CheckCircle2, CircleAlert, Play } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';

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
import { Permission } from '../../auth/permissions';
import { usePermission } from '../../auth/usePermission';
import { PageHeader } from '../../components/PageHeader';
import { StateView } from '../../components/StateView';
import { useProjectId } from '../../projects/ProjectContext';

export function ProjectProfilePage() {
  const projectId = useProjectId();
  const navigate = useNavigate();
  const { can } = usePermission();
  const [project, setProject] = useState<Project | null>(null);
  const [onboarding, setOnboarding] = useState<OnboardingStatus | null>(null);
  const [subjects, setSubjects] = useState<ProjectSubject[]>([]);
  const [domains, setDomains] = useState<ProjectDomain[]>([]);
  const [filings, setFilings] = useState<ICPFiling[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState('');
  const [basicForm] = Form.useForm();
  const [subjectForm] = Form.useForm();
  const [domainForm] = Form.useForm();
  const [icpForm] = Form.useForm();

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

  async function saveBasic() {
    await updateProject(projectId, await basicForm.validateFields());
    message.success('项目基础信息已保存');
    await load();
  }

  async function addSubject() {
    const values = await subjectForm.validateFields();
    await createProjectSubject(projectId, { ...values, verification_status: 'unverified', source: 'manual', evidence_summary: '' });
    subjectForm.resetFields();
    message.success('主体已添加');
    await load();
  }

  async function addDomain() {
    const values = await domainForm.validateFields();
    await createProjectDomain(projectId, { ...values, ownership_status: 'unverified', source: 'manual', evidence_summary: '' });
    domainForm.resetFields();
    message.success('主域名已添加');
    await load();
  }

  async function addICP() {
    const values = await icpForm.validateFields();
    await createICPFiling(projectId, { ...values, filing_type: 'filing', status: 'unverified', source: 'manual', evidence_summary: '' });
    icpForm.resetFields();
    message.success('ICP 备案已添加');
    await load();
  }

  async function activate() {
    try {
      await transitionProject(projectId, 'active');
      message.success('项目已激活');
      await load();
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
            summary={<Space wrap><Tag>{project.status}</Tag>{onboarding?.ready_to_activate ? <Tag color="green" icon={<CheckCircle2 size={13} />}>可激活</Tag> : <Tag color="gold" icon={<CircleAlert size={13} />}>资料待完善</Tag>}</Space>}
          />
          {onboarding && !onboarding.ready_to_activate ? <Alert type="warning" showIcon message="项目尚未满足激活条件" description={`待完成：${onboarding.missing.join('、')}`} action={<Button onClick={() => navigate(`/projects/${projectId}/discovery`)}>配置授权范围</Button>} /> : null}
          <Tabs items={[
            {
              key: 'basic', label: '基础信息', children: <>
                <Descriptions bordered size="small" column={2} className="project-profile-summary">
                  <Descriptions.Item label="状态">{project.status}</Descriptions.Item><Descriptions.Item label="负责人">{project.owner_user_id}</Descriptions.Item>
                  <Descriptions.Item label="主主体">{subjects.find((item) => item.is_primary)?.subject_name ?? '-'}</Descriptions.Item><Descriptions.Item label="主域名">{domains.find((item) => item.is_primary)?.domain ?? '-'}</Descriptions.Item>
                </Descriptions>
                <Form form={basicForm} layout="vertical" className="project-profile-form">
                  <Form.Item name="name" label="项目名称" rules={[{ required: true, max: 255 }]}><Input /></Form.Item>
                  <Form.Item name="owner_user_id" label="负责人用户 ID" rules={[{ required: true }]}><Input /></Form.Item>
                  <Form.Item name="business_unit" label="业务单元"><Input maxLength={128} /></Form.Item>
                  <Form.Item name="criticality" label="重要性"><Select options={['low', 'medium', 'high', 'critical'].map((value) => ({ value, label: value }))} /></Form.Item>
                  <Form.Item name="description" label="说明"><Input.TextArea rows={3} /></Form.Item>
                  {can(Permission.ProjectWrite) ? <Button type="primary" onClick={() => void saveBasic()}>保存基础信息</Button> : null}
                </Form>
              </>
            },
            {
              key: 'subjects', label: `主体 (${subjects.length})`, children: <Space direction="vertical" className="full-width" size={16}>
                <Table rowKey="id" pagination={false} dataSource={subjects} columns={[{ title: '单位名称', dataIndex: 'subject_name' }, { title: '类型', dataIndex: 'subject_type' }, { title: '登记代码', dataIndex: 'registration_code' }, { title: '主主体', dataIndex: 'is_primary', render: (value) => value ? <Tag color="blue">是</Tag> : '-' }, { title: '核验', dataIndex: 'verification_status' }]} />
                {can(Permission.ProjectWrite) ? <Form form={subjectForm} layout="inline" initialValues={{ subject_type: 'company', country_code: 'CN', is_primary: subjects.length === 0 }}><Form.Item name="subject_name" rules={[{ required: true }]}><Input placeholder="单位名称" /></Form.Item><Form.Item name="subject_type"><Select style={{ width: 130 }} options={['company', 'government', 'institution', 'individual', 'other'].map((value) => ({ value, label: value }))} /></Form.Item><Form.Item name="registration_code"><Input placeholder="统一社会信用代码" /></Form.Item><Form.Item name="country_code"><Input style={{ width: 72 }} /></Form.Item><Form.Item name="region"><Input placeholder="地区" /></Form.Item><Form.Item name="is_primary" valuePropName="checked"><Switch checkedChildren="主" /></Form.Item><Button type="primary" onClick={() => void addSubject()}>添加主体</Button></Form> : null}
              </Space>
            },
            {
              key: 'domains', label: `主域名 (${domains.length})`, children: <Space direction="vertical" className="full-width" size={16}>
                <Table rowKey="id" pagination={false} dataSource={domains} columns={[{ title: '域名', dataIndex: 'domain' }, { title: '主体', dataIndex: 'subject_id', render: (id) => subjects.find((item) => item.id === id)?.subject_name ?? '-' }, { title: '主域名', dataIndex: 'is_primary', render: (value) => value ? <Tag color="blue">是</Tag> : '-' }, { title: '归属核验', dataIndex: 'ownership_status' }]} />
                {can(Permission.ProjectWrite) ? <Form form={domainForm} layout="inline" initialValues={{ is_primary: domains.length === 0 }}><Form.Item name="domain" rules={[{ required: true }]}><Input placeholder="example.com" /></Form.Item><Form.Item name="subject_id"><Select style={{ width: 200 }} placeholder="关联主体" options={subjects.map((item) => ({ value: item.id, label: item.subject_name }))} /></Form.Item><Form.Item name="is_primary" valuePropName="checked"><Switch checkedChildren="主" /></Form.Item><Button type="primary" onClick={() => void addDomain()}>添加主域名</Button></Form> : null}
              </Space>
            },
            {
              key: 'icp', label: `ICP 备案 (${filings.length})`, children: <Space direction="vertical" className="full-width" size={16}>
                <Alert type="info" showIcon message="ICP 仅作为业务画像，不代表扫描授权。" />
                <Table rowKey="id" pagination={false} dataSource={filings} columns={[{ title: '备案号', dataIndex: 'filing_no' }, { title: '网站名称', dataIndex: 'website_name' }, { title: '主体', dataIndex: 'subject_id', render: (id) => subjects.find((item) => item.id === id)?.subject_name ?? '-' }, { title: '状态', dataIndex: 'status' }]} />
                {can(Permission.ProjectWrite) ? <Form form={icpForm} layout="inline"><Form.Item name="filing_no" rules={[{ required: true }]}><Input placeholder="ICP备案号" /></Form.Item><Form.Item name="website_name"><Input placeholder="网站名称" /></Form.Item><Form.Item name="subject_id" rules={[{ required: true }]}><Select style={{ width: 200 }} placeholder="备案主体" options={subjects.map((item) => ({ value: item.id, label: item.subject_name }))} /></Form.Item><Form.Item name="domain_profile_ids"><Select mode="multiple" style={{ minWidth: 220 }} placeholder="关联主域名" options={domains.map((item) => ({ value: item.id, label: item.domain }))} /></Form.Item><Button type="primary" onClick={() => void addICP()}>添加备案</Button></Form> : null}
              </Space>
            }
          ]} />
          {project.status !== 'active' && onboarding?.ready_to_activate && can(Permission.ProjectWrite) ? <div className="project-activate-bar"><Typography.Text>项目资料和授权范围已满足激活条件。</Typography.Text><Button type="primary" icon={<Play size={15} />} onClick={() => void activate()}>激活项目</Button></div> : null}
        </> : null}
      </StateView>
    </section>
  );
}
