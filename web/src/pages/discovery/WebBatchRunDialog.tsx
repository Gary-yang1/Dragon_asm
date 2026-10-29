import { useEffect, useRef, useState } from 'react';
import { Alert, Button, Modal, Space, Table, Typography } from 'antd';
import type { ColumnsType } from 'antd/es/table';
import { ChevronDown, ChevronRight } from 'lucide-react';

import { triggerTaskRun, type TaskRun, type TaskTemplate } from '../../api/discovery';
import { errorMessage } from '../../api/errorMessage';

type WebBatchRunDialogProps = {
  projectId: number;
  templates: TaskTemplate[] | null;
  onClose: () => void;
  onSubmitted: (runs: TaskRun[]) => void;
};

type BatchState = { status: 'waiting' | 'submitting' | 'submitted' | 'uncertain'; run?: TaskRun };
type BatchRow = { template: TaskTemplate; index: number } & BatchState;

function WebBatchRunSession({ projectId, templates, onClose, onSubmitted }: WebBatchRunDialogProps & { templates: TaskTemplate[] }) {
  const activeRef = useRef(true);
  const startedRef = useRef(false);
  const [pending, setPending] = useState(false);
  const [states, setStates] = useState<Record<number, BatchState>>({});
  const [submitted, setSubmitted] = useState<TaskRun[]>([]);
  const [failure, setFailure] = useState('');

  useEffect(() => {
    activeRef.current = true;
    return () => { activeRef.current = false; };
  }, []);

  // A repeated template in a materialization response must not start twice.
  const batches = templates.filter((template, index, all) => all.findIndex(item => item.id === template.id) === index);
  const targetCount = batches.reduce((total, template) => total + (template.config?.targets?.length ?? 0), 0);
  const invalidBatch = batches.some(template => template.project_id !== projectId || !template.enabled || !template.config?.targets?.length);
  const rows: BatchRow[] = batches.map((template, index) => ({ template, index, ...(states[template.id] ?? { status: 'waiting' }) }));
  const columns: ColumnsType<BatchRow> = [
    {
      title: '批次',
      dataIndex: 'index',
      width: 70,
      render: (index: number) => index + 1
    },
    {
      title: '目标示例',
      render: (_, row) => {
        const targets = row.template.config?.targets ?? [];
        return <div title={row.template.name}>
          <div style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{targets[0]?.value ?? '暂无目标'}</div>
          {targets.length > 1 && <Typography.Text type="secondary">另 {targets.length - 1} 个网址</Typography.Text>}
        </div>;
      }
    },
    {
      title: 'URL 目标',
      width: 100,
      align: 'right',
      render: (_, row) => row.template.config?.targets?.length ?? 0
    },
    {
      title: '提交状态',
      width: 160,
      render: (_, row) => {
        if (row.status === 'submitted') return <Typography.Text type="success">已提交 · #{row.run?.id}</Typography.Text>;
        if (row.status === 'submitting') return <Typography.Text>正在提交…</Typography.Text>;
        if (row.status === 'uncertain') return <Typography.Text type="warning">待核实执行记录</Typography.Text>;
        return <Typography.Text type="secondary">未提交</Typography.Text>;
      }
    }
  ];

  async function submitAll() {
    if (startedRef.current || invalidBatch || batches.length === 0) return;
    startedRef.current = true;
    setPending(true);
    const runs: TaskRun[] = [];
    for (const template of batches) {
      if (!activeRef.current) return;
      setStates(current => ({ ...current, [template.id]: { status: 'submitting' } }));
      try {
        const run = await triggerTaskRun(projectId, template.id);
        if (!activeRef.current) return;
        runs.push(run);
        setSubmitted([...runs]);
        setStates(current => ({ ...current, [template.id]: { status: 'submitted', run } }));
      } catch (error) {
        if (!activeRef.current) return;
        setStates(current => ({ ...current, [template.id]: { status: 'uncertain' } }));
        setFailure(`第 ${runs.length + 1} 批：${errorMessage(error)}。后续批次尚未提交；此批可能已经启动，请先检查执行记录，避免重复运行。`);
        setPending(false);
        return;
      }
    }
    if (!activeRef.current) return;
    setPending(false);
    onSubmitted(runs);
  }

  return (
    <Modal
      title="确认运行全部 Web 批次"
      open
      width={760}
      maskClosable={!pending}
      keyboard={!pending}
      closable={!pending}
      onCancel={() => { if (!pending) onClose(); }}
      footer={<Space>
        <Button disabled={pending} onClick={onClose}>{startedRef.current ? '关闭' : '取消'}</Button>
        {failure || submitted.length > 0 && !pending ? (
          <Button type="primary" onClick={() => onSubmitted(submitted)}>查看执行记录</Button>
        ) : (
          <Button type="primary" loading={pending} disabled={startedRef.current || invalidBatch || batches.length === 0} onClick={() => void submitAll()}>
            运行全部批次
          </Button>
        )}
      </Space>}
    >
      <Space direction="vertical" size={16} className="full-width">
        <Typography.Paragraph style={{ marginBottom: 0 }}>
          本次共 <Typography.Text strong>{targetCount}</Typography.Text> 个 URL 目标，分 <Typography.Text strong>{batches.length}</Typography.Text> 批提交。
          已提交的批次将进入任务队列，可在执行记录中查看进度与结果。
        </Typography.Paragraph>
        <Typography.Text type="secondary">本次操作不会修改授权范围。每个批次仍由服务端校验授权、运行权限及审批要求。</Typography.Text>
        {invalidBatch && <Alert type="warning" showIcon message="部分模板不可运行" description="请检查模板是否启用、目标是否为空，以及是否属于当前项目。" />}
        {failure && <Alert type="warning" showIcon message="已停止提交后续批次" description={failure} />}
        <Table<BatchRow>
          size="small"
          rowKey={row => row.template.id}
          columns={columns}
          dataSource={rows}
          pagination={false}
          scroll={{ y: 320 }}
          locale={{ emptyText: '暂无待运行批次' }}
          expandable={{
            columnWidth: 36,
            rowExpandable: row => Boolean(row.template.config?.targets?.length),
            expandIcon: ({ expanded, onExpand, record }) => <Button
              type="text"
              size="small"
              aria-label={`${expanded ? '收起' : '查看'}第 ${record.index + 1} 批全部目标`}
              aria-expanded={expanded}
              icon={expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
              onClick={event => onExpand(record, event)}
            />,
            expandedRowRender: row => <pre
              aria-label={`第 ${row.index + 1} 批完整 URL 目标`}
              style={{ margin: 0, maxHeight: 240, overflow: 'auto', whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', fontSize: 12, lineHeight: 1.7 }}
            >{row.template.config.targets.map(target => target.value).join('\n')}</pre>
          }}
        />
        <Typography.Text role="status" aria-live="polite" type="secondary">
          {startedRef.current ? `已提交 ${submitted.length} / ${batches.length} 批${pending ? '，正在提交后续批次…' : ''}` : '确认后开始提交任务。'}
        </Typography.Text>
      </Space>
    </Modal>
  );
}

export function WebBatchRunDialog(props: WebBatchRunDialogProps) {
  if (props.templates === null) return null;
  // Replacing the project or batch selection disposes the old submission loop.
  return <WebBatchRunSession key={`${props.projectId}:${props.templates.map(template => template.id).join(',')}`} {...props} templates={props.templates} />;
}
