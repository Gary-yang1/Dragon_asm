import { Alert, Button, Drawer, Form, Input, InputNumber, Select, Space, Statistic, Table, Tabs, Upload, message } from 'antd';
import { Download, FileUp, Upload as UploadIcon } from 'lucide-react';
import { useEffect, useMemo, useRef, useState } from 'react';

import {
  dryRunImport,
  importAssets,
  type DryRunReport,
  type ImportReport,
  type ImportRow
} from '../../api/assets';
import { assetTypeMeta, assetStatusMeta, describe } from '../../utils/taxonomy';
import { parseCSV, serializeCSV } from '../../utils/csv';

const importFields = ['asset_type', 'value', 'display_name', 'source', 'owner', 'business_unit', 'confidence', 'status'] as const;
type ImportField = (typeof importFields)[number];
type ImportMode = 'single' | 'paste' | 'file';

const sampleRows = `asset_type,value,display_name,source,owner,business_unit,confidence,status
domain,example.com,Example,manual,security,platform,95,active
ip,203.0.113.10,Edge IP,manual,ops,platform,90,active`;

type AssetImportDrawerProps = {
  projectId: number;
  open: boolean;
  onClose: () => void;
  onImported?: () => void;
};

export function AssetImportDrawer({ projectId, open, onClose, onImported }: AssetImportDrawerProps) {
  const [mode, setMode] = useState<ImportMode>('single');
  const [raw, setRaw] = useState(sampleRows);
  const [fileRows, setFileRows] = useState<string[][]>([]);
  const [mapping, setMapping] = useState<Partial<Record<ImportField, string>>>({});
  const [preview, setPreview] = useState<DryRunReport | null>(null);
  const [result, setResult] = useState<ImportReport | null>(null);
  const [pendingRows, setPendingRows] = useState<ImportRow[]>([]);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [committing, setCommitting] = useState(false);
  const revision = useRef(0);
  const [needsPreview, setNeedsPreview] = useState(false);
  const [form] = Form.useForm<ImportRow>();

  const fileHeaders = fileRows[0] ?? [];
  const fileData = fileRows.slice(1);
  const reportRows = result?.rows ?? preview?.rows ?? [];

  const stats = useMemo(() => result ? [
    ['总数', result.total], ['成功', result.success], ['失败', result.failed]
  ] : preview ? [
    ['总数', preview.total], ['新增', preview.new], ['更新', preview.update], ['重复', preview.duplicate], ['失败', preview.failed]
  ] : [], [preview, result]);

  useEffect(() => {
    revision.current += 1;
    setPreview(null);
    setResult(null);
    setPendingRows([]);
    setError('');
    setLoading(false);
    setCommitting(false);
    setNeedsPreview(false);
    return () => { revision.current += 1; };
  }, [projectId, open]);

  function resetReports() {
    revision.current += 1;
    setLoading(false);
    setNeedsPreview(true);
    setPreview(null);
    setResult(null);
    setPendingRows([]);
    setError('');
  }

  async function rowsForMode() {
    if (mode === 'single') return [normalizeRow(await form.validateFields())];
    if (mode === 'paste') return rowsFromCSV(parseCSV(raw));
    if (!fileRows.length) throw new Error('请选择 CSV 文件');
    return recordsToRows(fileHeaders, fileData, mapping);
  }

  async function runPreview() {
    if (committing) return;
    resetReports();
    const requestRevision = revision.current;
    setLoading(true);
    try {
      const rows = await rowsForMode();
      if (requestRevision !== revision.current) return;
      const report = await dryRunImport(projectId, rows);
      if (requestRevision !== revision.current) return;
      setPendingRows(rows);
      setPreview(report);
      setNeedsPreview(false);
    } catch (err) {
      if (requestRevision !== revision.current) return;
      if (!(typeof err === 'object' && err !== null && 'errorFields' in err)) {
        setError(err instanceof Error ? err.message : '导入预览失败');
      }
    } finally {
      if (requestRevision === revision.current) setLoading(false);
    }
  }

  async function commit() {
    if (!pendingRows.length || !preview || loading || committing) return;
    const requestRevision = revision.current;
    setCommitting(true);
    setError('');
    try {
      const report = await importAssets(projectId, pendingRows);
      if (requestRevision !== revision.current) return;
      setResult(report);
      setPreview(null);
      setPendingRows([]);
      message.success(`已导入 ${report.success} 条资产`);
      onImported?.();
    } catch (err) {
      if (requestRevision === revision.current) setError(err instanceof Error ? err.message : '资产导入失败');
    } finally {
      if (requestRevision === revision.current) setCommitting(false);
    }
  }

  function readFile(file: globalThis.File) {
    resetReports();
    const requestRevision = revision.current;
    setLoading(true);
    void file.text().then((text) => {
      if (requestRevision !== revision.current) return;
      const rows = parseCSV(text);
      if (rows.length < 2) throw new Error('CSV 至少需要表头和一行数据');
      setFileRows(rows);
      const headers = rows[0];
      setMapping(Object.fromEntries(importFields.map((field) => [field, headers.includes(field) ? field : undefined])) as Partial<Record<ImportField, string>>);
    }).catch((err: unknown) => {
      if (requestRevision !== revision.current) return;
      setFileRows([]);
      setError(err instanceof Error ? err.message : 'CSV 文件读取失败');
    }).finally(() => { if (requestRevision === revision.current) setLoading(false); });
    return false;
  }

  function downloadTemplate() {
    downloadCSV('asset-import-template.csv', serializeCSV([[...importFields], ['domain', 'example.com', 'Example', 'manual', '', '', 90, 'active']]));
  }

  function downloadResult() {
    if (!result) return;
    downloadCSV('asset-import-result.csv', serializeCSV([
      ['index', 'status', 'asset_id', 'asset_key', 'error'],
      ...result.rows.map((row) => [row.index, row.status, row.asset_id, row.asset_key, row.error])
    ]));
  }

  return (
    <Drawer title="导入资产" open={open} onClose={() => { if (!committing) onClose(); }} width={820} destroyOnClose={false}>
      <Space direction="vertical" size={16} className="full-width">
        {error ? <Alert type="error" message={error} showIcon /> : null}
        <Tabs
          activeKey={mode}
          onChange={(key) => { if (!committing) { setMode(key as ImportMode); resetReports(); } }}
          items={[
            {
              key: 'single', label: '单条录入', children: (
                <Form form={form} disabled={committing} onValuesChange={resetReports} layout="vertical" initialValues={{ asset_type: 'domain', source: 'manual', confidence: 90, status: 'active' }}>
                  <div className="asset-import-grid">
                    <Form.Item name="asset_type" label="资产类型" rules={[{ required: true }]}><Select options={['domain', 'subdomain', 'ip', 'port', 'service', 'web', 'certificate', 'cloud_resource', 'third_party'].map((value) => ({ value, label: describe(assetTypeMeta, value).label }))} /></Form.Item>
                    <Form.Item name="value" label="资产值" rules={[{ required: true }]}><Input /></Form.Item>
                    <Form.Item name="display_name" label="显示名称"><Input /></Form.Item>
                    <Form.Item name="source" label="来源"><Input /></Form.Item>
                    <Form.Item name="owner" label="负责人"><Input /></Form.Item>
                    <Form.Item name="business_unit" label="业务单元"><Input /></Form.Item>
                    <Form.Item name="confidence" label="置信度"><InputNumber min={0} max={100} className="full-width" /></Form.Item>
                    <Form.Item name="status" label="状态"><Select options={['active', 'inactive', 'ignored'].map((value) => ({ value, label: describe(assetStatusMeta, value).label }))} /></Form.Item>
                  </div>
                </Form>
              )
            },
            { key: 'paste', label: '批量粘贴', children: <Input.TextArea disabled={committing} aria-label="导入内容" value={raw} onChange={(event) => { setRaw(event.target.value); resetReports(); }} rows={10} /> },
            {
              key: 'file', label: 'CSV 文件', children: <Space direction="vertical" className="full-width" size={14}>
                <Upload.Dragger disabled={committing} accept=".csv,text/csv" maxCount={1} beforeUpload={readFile} showUploadList={false}><FileUp size={24} /><div>选择 CSV 文件</div></Upload.Dragger>
                {fileHeaders.length ? <div className="asset-field-mapping">{importFields.map((field) => <label key={field}><span>{field}</span><Select allowClear value={mapping[field]} options={fileHeaders.map((header) => ({ value: header, label: header }))} disabled={committing} onChange={(value) => { setMapping((current) => ({ ...current, [field]: value })); resetReports(); }} /></label>)}</div> : null}
              </Space>
            }
          ]}
          tabBarExtraContent={<Button icon={<Download size={15} />} onClick={downloadTemplate}>模板</Button>}
        />
        <Space>
          <Button type="primary" icon={<UploadIcon size={15} />} disabled={committing} onClick={() => void runPreview()} loading={loading}>预览</Button>
          <Button type="primary" disabled={loading || committing || !preview || preview.failed === preview.total} onClick={() => void commit()} loading={committing}>确认导入</Button>
          {result ? <Button icon={<Download size={15} />} onClick={downloadResult}>结果</Button> : null}
        </Space>
        {needsPreview && !loading && <span className="secondary-text" role="status">内容已修改，请重新预览后确认导入。</span>}
        {stats.length ? <div className="import-stats">{stats.map(([title, value]) => <Statistic key={title} title={title} value={value} />)}</div> : null}
        {reportRows.length ? <Table
          rowKey={(row) => `${row.index}-${row.status}`}
          size="small"
          pagination={{ pageSize: 20 }}
          dataSource={reportRows}
          columns={[
            { title: '#', dataIndex: 'index', width: 64 },
            { title: '状态', dataIndex: 'status' },
            { title: '类型', dataIndex: 'asset_type' },
            { title: '值', dataIndex: 'value' },
            { title: '资产 Key', dataIndex: 'asset_key' },
            { title: '错误', dataIndex: 'error' }
          ]}
        /> : null}
      </Space>
    </Drawer>
  );
}

function rowsFromCSV(rows: string[][]) {
  if (!rows.length) return [];
  const hasHeader = rows[0].includes('asset_type') && rows[0].includes('value');
  if (hasHeader) {
    const headers = rows[0];
    const mapping = Object.fromEntries(importFields.map((field) => [field, headers.includes(field) ? field : undefined])) as Partial<Record<ImportField, string>>;
    return recordsToRows(headers, rows.slice(1), mapping);
  }
  return rows.map((row) => rowToImport(Object.fromEntries(importFields.map((field, index) => [field, row[index]]))));
}

function recordsToRows(headers: string[], records: string[][], mapping: Partial<Record<ImportField, string>>) {
  if (!mapping.asset_type || !mapping.value) throw new Error('必须映射 asset_type 和 value');
  return records.map((record) => {
    const source = Object.fromEntries(importFields.map((field) => {
      const header = mapping[field];
      return [field, header ? record[headers.indexOf(header)] : undefined];
    }));
    return rowToImport(source);
  });
}

function rowToImport(source: Record<string, string | undefined>): ImportRow {
  if (!source.asset_type || !source.value) throw new Error('每行至少需要 asset_type 和 value');
  const confidence = source.confidence === undefined || source.confidence === '' ? undefined : Number(source.confidence);
  if (confidence !== undefined && (!Number.isFinite(confidence) || confidence < 0 || confidence > 100)) throw new Error('confidence 必须在 0-100 之间');
  return normalizeRow({
    asset_type: source.asset_type,
    value: source.value,
    display_name: source.display_name,
    source: source.source,
    owner: source.owner,
    business_unit: source.business_unit,
    confidence,
    status: source.status
  });
}

function normalizeRow(row: ImportRow): ImportRow {
  return { ...row, asset_type: row.asset_type.trim(), value: row.value.trim() };
}

function downloadCSV(filename: string, content: string) {
  const url = URL.createObjectURL(new globalThis.Blob([content], { type: 'text/csv;charset=utf-8' }));
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}
