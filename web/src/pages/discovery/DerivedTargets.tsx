import {
  Alert,
  App as AntApp,
  Button,
  Checkbox,
  Input,
  Modal,
  Segmented,
  Select,
  Space,
  Table,
  Tag,
  Typography,
} from "antd";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  authorizeDerivedTargets,
  createContinuation,
  listDerivedTargets,
  type DerivedTarget,
  type DerivedTargetPage,
  type TaskTemplate,
} from "../../api/discovery";
import { errorMessage } from "../../api/errorMessage";
import { Permission } from "../../auth/permissions";
import { usePermission } from "../../auth/usePermission";
import { discoveryPurpose } from "./ExecutionSummary";

const targetKinds: Record<string, string> = {
  dns: "domain",
  passive_intel: "domain",
  port_probe: "ip",
  web_probe: "url",
  fingerprint: "url",
};
const labels = {
  inherited: "已继承",
  pending: "待确认",
  excluded: "已排除",
  blocked: "不可执行",
};
const typeLabels = { domain: "域名", ip: "IP", url: "网址" };

type Props = {
  projectId: number;
  runId: number | null;
  onClose: () => void;
  onCreated: (template: TaskTemplate) => void;
  onScopeUpdated: () => void;
  onPrepareWeb?: (scopeId:number) => void;
};
export function DerivedTargets({
  projectId,
  runId,
  onClose,
  onCreated,
  onScopeUpdated,
  onPrepareWeb,
}: Props) {
  const { can } = usePermission();
  const { message } = AntApp.useApp();
  const [page, setPage] = useState<DerivedTargetPage>();
  const [cursor, setCursor] = useState(0);
  const [history, setHistory] = useState<number[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [section, setSection] = useState<"inherited" | "pending" | "excluded">(
    "inherited",
  );
  const [taskType, setTaskType] = useState("dns");
  const [selected, setSelected] = useState<number[]>([]);
  const [pending, setPending] = useState(false);
  const pendingRef = useRef(false);
  const generation = useRef(0);
  const [authorizationOpen, setAuthorizationOpen] = useState(false);
  const [accepted, setAccepted] = useState(false);
  const [reason, setReason] = useState(
    "确认所选目标属于本项目授权范围，用于后续资产发现",
  );
  const [refresh, setRefresh] = useState(0);
  const canContinue = can(Permission.DiscoveryRun);
  const canAuthorize = can(Permission.ScopeWrite);

  useEffect(() => {
    generation.current += 1;
    setCursor(0);
    setHistory([]);
    setSection("inherited");
    setTaskType("dns");
    setSelected([]);
    setAuthorizationOpen(false);
    setAccepted(false);
    setPage(undefined);
    setError("");
    setPending(false);
    pendingRef.current = false;
    return () => {
      generation.current += 1;
    };
  }, [projectId, runId]);
  useEffect(() => {
    if (runId === null) return;
    const controller = new globalThis.AbortController();
    setLoading(true);
    setPage(undefined);
    setSelected([]);
    setError("");
    listDerivedTargets(projectId, runId, cursor, controller.signal)
      .then((value) => {
        if (!controller.signal.aborted) setPage(value);
      })
      .catch((err) => {
        if (!controller.signal.aborted) setError(errorMessage(err));
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [projectId, runId, cursor, refresh]);
  const rows = useMemo(
    () =>
      (page?.items ?? []).filter((item) =>
        section === "excluded"
          ? ["excluded", "blocked"].includes(item.status)
          : item.status === section,
      ),
    [page, section],
  );
  useEffect(() => {
    // Only covered targets of the chosen task type are selected automatically.
    setSelected(
      section === "inherited"
        ? rows
            .filter((item) => item.target_type === targetKinds[taskType])
            .map((item) => item.observation_id)
        : [],
    );
  }, [rows, taskType, section]);
  const selectedRows = rows.filter((item) =>
    selected.includes(item.observation_id),
  );
  const close = useCallback(() => {
    if (!pendingRef.current) onClose();
  }, [onClose]);
  async function create() {
    if (!page || runId === null || !selected.length || pendingRef.current)
      return;
    const sequence = generation.current;
    pendingRef.current = true;
    setPending(true);
    setError("");
    try {
      const template = await createContinuation(projectId, runId, {
        task_type: taskType,
        observation_ids: selected,
        scope_fingerprint: page.scope_fingerprint,
      });
      if (sequence !== generation.current) return;
      message.success("已生成接续配置，目标已自动带入");
      onCreated(template);
    } catch (err) {
      if (sequence === generation.current) setError(errorMessage(err));
    } finally {
      if (sequence === generation.current) {
        pendingRef.current = false;
        setPending(false);
      }
    }
  }
  async function authorize() {
    if (
      !page ||
      runId === null ||
      !selected.length ||
      !accepted ||
      !reason.trim() ||
      pendingRef.current
    )
      return;
    const sequence = generation.current;
    pendingRef.current = true;
    setPending(true);
    setError("");
    try {
      await authorizeDerivedTargets(projectId, runId, {
        observation_ids: selected,
        scope_fingerprint: page.scope_fingerprint,
        reason: reason.trim(),
      });
      if (sequence !== generation.current) return;
      setAuthorizationOpen(false);
      setAccepted(false);
      setSection("inherited");
      setRefresh((value) => value + 1);
      onScopeUpdated();
      message.success("已加入父授权，原有效期和排除项保持不变");
    } catch (err) {
      if (sequence === generation.current) {
        setAuthorizationOpen(false);
        setError(errorMessage(err));
      }
    } finally {
      if (sequence === generation.current) {
        pendingRef.current = false;
        setPending(false);
      }
    }
  }
  const inheritedCount =
    page?.items.filter((item) => item.status === "inherited").length ?? 0;
  const pendingCount =
    page?.items.filter((item) => item.status === "pending").length ?? 0;
  const excludedCount =
    (page?.items.length ?? 0) - inheritedCount - pendingCount;
  return (
    <>
      <Modal
        title={`继承结果继续发现 · #${runId ?? ""}`}
        open={runId !== null}
        onCancel={close}
        width={960}
        centered
        className="discovery-task-modal"
        destroyOnHidden
        footer={
          <Space wrap>
            <Button disabled={pending} onClick={close}>
              关闭
            </Button>
            {section === "inherited" && canContinue && (
              <Button
                type="primary"
                loading={pending}
                disabled={
                  loading ||
                  !selected.length ||
                  !page?.parent_active ||
                  !page?.source_complete
                }
                onClick={() => void create()}
              >
                生成接续配置（{selected.length}）
              </Button>
            )}
            {section === "pending" && canAuthorize && (
              <Button
                disabled={loading || !selected.length || pending}
                onClick={() => {
                  setAccepted(false);
                  setAuthorizationOpen(true);
                }}
              >
                批量确认授权（{selected.length}）
              </Button>
            )}
          </Space>
        }
      >
        <Space direction="vertical" size={16} className="full-width">
          <Typography.Paragraph type="secondary">
            从前一步结果中选择目标，后续任务继续使用父授权。不会自动运行扫描，也不会把范围外目标自动变成已授权。
          </Typography.Paragraph>
          {page && onPrepareWeb && canContinue && page.parent_active && page.source_complete && <Alert type="info" showIcon message="继续识别网站，无需逐条选择域名" description="按父授权匹配项目已有域名和网站，准备全部 Web 目标并自动分批。域名在本表的授权状态不等同于 URL 规则的覆盖状态，下一步会按实际规则检查。" action={<Button type="primary" disabled={pending || loading} onClick={() => onPrepareWeb(page.parent_scope_id)}>准备全部 Web 目标</Button>} />}
          {error && (
            <Alert
              type="error"
              showIcon
              message="操作未完成"
              description={error}
              action={
                <Button
                  disabled={pending}
                  onClick={() => setRefresh((value) => value + 1)}
                >
                  刷新目标
                </Button>
              }
            />
          )}
          {page && (
            <>
              <div className="discovery-summary-line">
                <span>
                  父授权 <strong>{page.parent_scope_name}</strong>
                </span>
                <span>
                  有效期至 {new Date(page.valid_until).toLocaleString()}
                </span>
              </div>
              {(!page.parent_active || !page.source_complete) && (
                <Alert
                  type="warning"
                  showIcon
                  message={
                    !page.parent_active
                      ? "父授权当前不可用"
                      : "来源任务尚未完成或未成功"
                  }
                  description="下发前会重新检查父授权；授权停用、过期或命中排除规则的目标不能继续执行。"
                />
              )}
            </>
          )}
          <Segmented
            block
            value={section}
            disabled={pending}
            onChange={(value) => setSection(value as typeof section)}
            options={[
              { value: "inherited", label: `已继承 ${inheritedCount}` },
              { value: "pending", label: `待确认 ${pendingCount}` },
              { value: "excluded", label: `排除 / 不可用 ${excludedCount}` },
            ]}
          />
          {section === "inherited" && (
            <div className="discovery-section-heading">
              <label htmlFor="continuation-task-type">下一步做什么</label>
              <Select
                id="continuation-task-type"
                aria-label="下一步做什么"
                value={taskType}
                disabled={pending}
                onChange={setTaskType}
                style={{ width: 260 }}
                options={Object.keys(targetKinds).map((value) => ({
                  value,
                  label: discoveryPurpose[value as TaskTemplate["task_type"]],
                }))}
              />
            </div>
          )}
          {section === "inherited" && (
            <Typography.Text type="secondary">
              默认勾选适合当前任务类型的目标。仅继承授权不代表主动任务已通过审批或归属校验；这些策略在启动与下发时继续生效。
            </Typography.Text>
          )}
          {section === "pending" && (
            <Alert
              type="info"
              showIcon
              message="域名解析关系不等于整台 IP 主机的授权"
              description={
                canAuthorize
                  ? "确认目标属于你的授权范围后，可批量加入父授权。CDN、共享主机及第三方资产需核实，排除项无法在这里覆盖。"
                  : "请有授权管理权限的项目负责人确认这些目标。"
              }
            />
          )}
          <Table<DerivedTarget>
            size="small"
            rowKey="observation_id"
            loading={loading}
            dataSource={rows}
            pagination={false}
            scroll={{ x: 750 }}
            rowSelection={
              section === "excluded" || (section === "pending" && !canAuthorize)
                ? undefined
                : {
                    selectedRowKeys: selected,
                    onChange: (keys) => setSelected(keys as number[]),
                    getCheckboxProps: (item) => ({
                      disabled:
                        pending ||
                        (section === "inherited" &&
                          item.target_type !== targetKinds[taskType]),
                    }),
                  }
            }
            columns={[
              {
                title: "目标",
                dataIndex: "value",
                width: 220,
                render: (value: string, item) => (
                  <>
                    <Typography.Text>{value}</Typography.Text>
                    <br />
                    <Typography.Text type="secondary">
                      {typeLabels[item.target_type]}
                    </Typography.Text>
                  </>
                ),
              },
              {
                title: "授权状态",
                dataIndex: "status",
                width: 110,
                render: (_, item) => (
                  <Tag
                    color={
                      item.status === "inherited"
                        ? "success"
                        : item.status === "pending"
                          ? "warning"
                          : "default"
                    }
                  >
                    {labels[item.status]}
                  </Tag>
                ),
              },
              { title: "依据", dataIndex: "reason", width: 280 },
              {
                title: "发现来源",
                dataIndex: "provider",
                render: (_, item) => (
                  <>
                    {item.provider || "未标明"}
                    <br />
                    <Typography.Text type="secondary">
                      {new Date(item.observed_at).toLocaleString()}
                    </Typography.Text>
                  </>
                ),
              },
            ]}
            locale={{
              emptyText: loading
                ? "正在读取发现证据…"
                : page?.items.length
                  ? "当前分类没有目标；可查看其他分类或切换下一步任务。"
                  : "该页没有可派生的结构化目标。旧任务可能未保留来源证据，可重新执行一次发现任务。",
            }}
          />
          <Space wrap>
            <Typography.Text type="secondary">
              当前页统计，每批最多 100 条来源记录。
            </Typography.Text>
            <Button
              disabled={!history.length || loading || pending}
              onClick={() => {
                setCursor(history[history.length - 1]);
                setHistory((value) => value.slice(0, -1));
              }}
            >
              上一批
            </Button>
            <Button
              disabled={!page?.next_cursor || loading || pending}
              onClick={() => {
                setHistory((value) => [...value, cursor]);
                setCursor(page!.next_cursor);
              }}
            >
              下一批
            </Button>
          </Space>
        </Space>
      </Modal>
      <Modal
        title="确认扩展父授权"
        open={authorizationOpen}
        centered
        className="discovery-task-modal"
        onCancel={() => {
          if (!pending) setAuthorizationOpen(false);
        }}
        onOk={() => void authorize()}
        okText="确认加入父授权"
        confirmLoading={pending}
        okButtonProps={{ disabled: !accepted || !reason.trim() || pending }}
        cancelButtonProps={{ disabled: pending }}
      >
        <Space direction="vertical" size={16} className="full-width">
          <Typography.Paragraph>
            将以下 {selectedRows.length} 个目标以精确匹配加入“
            {page?.parent_scope_name}
            ”，用于该授权允许的发现操作。原有效期和排除项不变。
          </Typography.Paragraph>
          <ul>
            {selectedRows.map((item) => (
              <li key={item.observation_id}>
                {item.value}（{typeLabels[item.target_type]}）
              </li>
            ))}
          </ul>
          <label htmlFor="derived-authorization-reason">授权说明</label>
          <Input.TextArea
            id="derived-authorization-reason"
            aria-label="授权说明"
            value={reason}
            onChange={(event) => setReason(event.target.value)}
            maxLength={500}
            disabled={pending}
          />
          <Checkbox
            checked={accepted}
            disabled={pending}
            onChange={(event) => setAccepted(event.target.checked)}
          >
            我已核实并有权授权这些目标
          </Checkbox>
        </Space>
      </Modal>
    </>
  );
}
