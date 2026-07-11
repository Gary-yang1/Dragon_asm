import { Alert, Button, Form, Input, Result, Select, Space, Steps, Switch, Typography, message } from 'antd';
import { ArrowLeft, CheckCircle2, FolderKanban, Radar, Save } from 'lucide-react';
import { useState } from 'react';
import { useNavigate } from 'react-router-dom';

import {
  createICPFiling,
  createProject,
  createProjectDomain,
  createProjectSubject,
  type Project,
  type ProjectDomain,
  type ProjectSubject
} from '../../api/projects';
import { errorMessage } from '../../api/errorMessage';
import { useAuth } from '../../auth/AuthProvider';
import { PageHeader } from '../../components/PageHeader';

type WizardValues = {
  project_code: string;
  name: string;
  business_unit: string;
  criticality: Project['criticality'];
  description?: string;
  subject_name: string;
  subject_type: 'company' | 'government' | 'institution' | 'individual' | 'other';
  registration_code?: string;
  country_code: string;
  region?: string;
  domain: string;
  ownership_verified?: boolean;
  filing_no?: string;
  website_name?: string;
};

type CreatedResources = {
  project?: Project;
  subject?: ProjectSubject;
  domain?: ProjectDomain;
  filingCreated?: boolean;
};

export function ProjectCreatePage() {
  const navigate = useNavigate();
  const { user } = useAuth();
  const [form] = Form.useForm<WizardValues>();
  const [step, setStep] = useState(0);
  const [saving, setSaving] = useState(false);
  const [created, setCreated] = useState<CreatedResources>({});
  const [saveError, setSaveError] = useState('');

  async function next() {
    const fields: Array<keyof WizardValues> = step === 0
      ? ['project_code', 'name', 'business_unit', 'criticality']
      : step === 1
        ? ['subject_name', 'subject_type', 'country_code']
        : ['domain'];
    try {
      await form.validateFields(fields);
    } catch {
      return;
    }
    setStep((current) => Math.min(2, current + 1));
  }

  async function finish() {
    let values: WizardValues;
    try {
      values = await form.validateFields();
    } catch {
      return;
    }
    setSaving(true);
    setSaveError('');
    const resources = { ...created };
    try {
      if (!resources.project) {
        resources.project = await createProject({
          project_code: values.project_code,
          name: values.name,
          owner_user_id: user?.id,
          business_unit: values.business_unit,
          criticality: values.criticality,
          description: values.description ?? ''
        });
        setCreated({ ...resources });
      }
      if (!resources.subject) {
        resources.subject = await createProjectSubject(resources.project.id, {
          subject_name: values.subject_name,
          subject_type: values.subject_type,
          registration_code: values.registration_code ?? '',
          country_code: values.country_code.toUpperCase(),
          region: values.region ?? '',
          is_primary: true,
          verification_status: 'unverified',
          source: 'manual',
          evidence_summary: ''
        });
        setCreated({ ...resources });
      }
      if (!resources.domain) {
        resources.domain = await createProjectDomain(resources.project.id, {
          domain: values.domain,
          subject_id: resources.subject.id,
          is_primary: true,
          ownership_status: values.ownership_verified ? 'verified' : 'unverified',
          source: 'manual',
          evidence_summary: ''
        });
        setCreated({ ...resources });
      }
      if (values.filing_no && !resources.filingCreated) {
        await createICPFiling(resources.project.id, {
          subject_id: resources.subject.id,
          filing_no: values.filing_no,
          filing_type: 'filing',
          website_name: values.website_name ?? '',
          status: 'unverified',
          source: 'manual',
          evidence_summary: '',
          domain_profile_ids: [resources.domain.id]
        });
        resources.filingCreated = true;
        setCreated({ ...resources });
      }
      globalThis.dispatchEvent(new Event('asm:projects-changed'));
      localStorage.setItem('asm.lastProject', String(resources.project.id));
      message.success('项目草稿及基础资料已创建');
      setStep(3);
    } catch (err) {
      setCreated({ ...resources });
      setSaveError(errorMessage(err));
    } finally {
      setSaving(false);
    }
  }

  const projectId = created.project?.id;

  return (
    <section className="page-surface project-create-page">
      <PageHeader
        title="创建项目"
        subtitle="建立项目边界、业务主体和首个主域名"
        actions={<Button icon={<ArrowLeft size={16} />} onClick={() => navigate('/projects')}>返回项目列表</Button>}
      />
      <div className="project-create-shell">
        <Steps current={step} items={[{ title: '基础信息' }, { title: '主体信息' }, { title: '域名与备案' }, { title: '完成' }]} />
        {created.project && step < 3 ? <Alert type="warning" showIcon message={`项目草稿 ${created.project.name} 已创建`} description="后续资料保存失败时可在本页继续，或进入项目资料页补充，不会重复创建项目。" /> : null}
        {saveError ? <Alert type="error" showIcon message="保存未完成" description={saveError} action={projectId ? <Button onClick={() => navigate(`/projects/${projectId}/profile`)}>进入草稿</Button> : undefined} /> : null}
        {step < 3 ? (
          <Form form={form} layout="vertical" className="project-create-form" initialValues={{ criticality: 'medium', subject_type: 'company', country_code: 'CN' }}>
            <div hidden={step !== 0} className="project-create-fields">
              <Form.Item name="project_code" label="项目编码" rules={[{ required: true }, { pattern: /^[a-z0-9][a-z0-9_-]{0,63}$/, message: '仅支持小写字母、数字、下划线和短横线' }]}><Input disabled={Boolean(created.project)} /></Form.Item>
              <Form.Item name="name" label="项目名称" rules={[{ required: true, max: 255 }]}><Input disabled={Boolean(created.project)} /></Form.Item>
              <Form.Item label="项目负责人"><Input value={user?.displayName || user?.username} disabled /></Form.Item>
              <Form.Item name="business_unit" label="业务单元" rules={[{ required: true, max: 128 }]}><Input disabled={Boolean(created.project)} /></Form.Item>
              <Form.Item name="criticality" label="重要性"><Select disabled={Boolean(created.project)} options={[['low', '低'], ['medium', '中'], ['high', '高'], ['critical', '关键']].map(([value, label]) => ({ value, label }))} /></Form.Item>
              <Form.Item name="description" label="说明"><Input.TextArea disabled={Boolean(created.project)} rows={3} maxLength={2000} /></Form.Item>
            </div>
            <div hidden={step !== 1} className="project-create-fields">
              <Alert type="info" showIcon message="主体是单位或企业等业务实体，不是平台项目负责人。" />
              <Form.Item name="subject_name" label="单位名称" rules={[{ required: true, max: 255 }]}><Input disabled={Boolean(created.subject)} /></Form.Item>
              <Form.Item name="subject_type" label="主体类型"><Select disabled={Boolean(created.subject)} options={[['company', '企业'], ['government', '政府'], ['institution', '事业单位'], ['individual', '个人'], ['other', '其他']].map(([value, label]) => ({ value, label }))} /></Form.Item>
              <Form.Item name="registration_code" label="统一社会信用代码"><Input disabled={Boolean(created.subject)} maxLength={64} /></Form.Item>
              <Form.Item name="country_code" label="国家/地区代码" rules={[{ required: true, len: 2 }]}><Input disabled={Boolean(created.subject)} maxLength={2} /></Form.Item>
              <Form.Item name="region" label="所在地区"><Input disabled={Boolean(created.subject)} maxLength={128} /></Form.Item>
            </div>
            <div hidden={step !== 2} className="project-create-fields">
              <Alert type="warning" showIcon message="主域名和 ICP 用于项目画像，不代表扫描授权。" />
              <Form.Item
                name="domain"
                label="主域名"
                rules={[
                  { required: true, max: 253 },
                  {
                    pattern: /^(?=.{1,253}$)(?!.*\.\.)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:[a-zA-Z]{2,63}|xn--[a-zA-Z0-9-]{2,59})$/,
                    message: '请输入合法的根域名，例如 example.com'
                  }
                ]}
              ><Input disabled={Boolean(created.domain)} placeholder="example.com" /></Form.Item>
              <Form.Item name="ownership_verified" label="归属已核验" valuePropName="checked"><Switch disabled={Boolean(created.domain)} /></Form.Item>
              <Form.Item name="filing_no" label="ICP 备案号（可选）"><Input disabled={created.filingCreated} maxLength={128} /></Form.Item>
              <Form.Item name="website_name" label="备案网站名称"><Input disabled={created.filingCreated} maxLength={255} /></Form.Item>
            </div>
          </Form>
        ) : (
          <Result
            status="success"
            icon={<CheckCircle2 size={52} />}
            title="项目草稿已创建"
            subTitle="下一步需要配置有效授权范围，满足启用条件后再激活项目。"
            extra={projectId ? [
              <Button key="scope" type="primary" icon={<Radar size={16} />} onClick={() => navigate(`/projects/${projectId}/discovery`)}>配置授权范围</Button>,
              <Button key="profile" icon={<FolderKanban size={16} />} onClick={() => navigate(`/projects/${projectId}/profile`)}>查看项目资料</Button>,
              <Button key="overview" onClick={() => navigate(`/projects/${projectId}/overview`)}>进入项目</Button>
            ] : undefined}
          />
        )}
        {step < 3 ? <div className="project-create-actions">
          <Typography.Text type="secondary">步骤 {step + 1} / 3</Typography.Text>
          <Space>
            <Button disabled={step === 0 || saving} onClick={() => setStep((current) => current - 1)}>上一步</Button>
            {step < 2
              ? <Button type="primary" onClick={() => void next()}>下一步</Button>
              : <Button type="primary" icon={<Save size={16} />} loading={saving} onClick={() => void finish()}>{created.project ? '继续保存' : '创建项目草稿'}</Button>}
          </Space>
        </div> : null}
      </div>
    </section>
  );
}
