# Baiyan 外部引擎接入 ToDo（MCP 已暂缓）

> 更新日期：2026-07-14
> 依据：`docs/Baiyan外部引擎接入与MCP改造计划.md` v0.1，以及对当前 ASM/Baiyan 代码的只读审计。
> 使用方式：当前 Goal 按 `EXT-00` → `EXT-09` 执行；每个 `EXT-*` 是独立检查点。
> Goal 起点：`EXT-00 Engine Contract v1 冻结`；Goal 终点：`EXT-09 ASM + Baiyan E2E` 完成并通过总体验证。
> 范围决策：用户于 2026-07-14 决定取消/暂缓 MCP，`EXT-10` 不属于当前 Goal；`EXT-11` 主动能力同样排除，必须另开目标并经过安全审批。

## 当前基线

已存在、不得重复实现：

- ASM 已有 Scope、TaskTemplate、TaskRun 的 migration、repository、service 与状态机。
- ASM 已有 `EngineAdapter` 及 HTTP `Dispatch/Status/Cancel` 基础实现。
- ASM 已有 HMAC callback、`(project_id, run_id, seq)` 记录、asynq ingest handler、超时 reconcile handler。
- ASM 已有 asset、asset_relation、exposure、change_event、risk、audit 等基础模块。
- Baiyan 源码快照已位于 `engines/baiyan/`，当前主要入口仍是 CLI。

当前已确认缺口：

- Discovery Scope/Template/Run 管理能力没有挂载受保护 HTTP API，OpenAPI 也未登记。
- 没有 `dispatch_task_run` producer/consumer；创建 run 后不会自动下发。
- callback URL 仍由调用者传入，尚无可信配置生成器。
- 配置名不统一：代码使用 `DISCOVERY_*`，`.env.example/docker-compose.yml` 仍存在 `ENGINE_*`。
- callback handler 没有请求体上限，JSON 允许未知字段，尚无 `schema_version`、`relations`、provider error 等 v1 DTO。
- callback 先插入数据库再入 Redis；入队失败后重复回调会直接返回 duplicate，且数据库未保存 payload，存在永久丢失窗口。
- final callback 入库完成后不会可靠地将 TaskRun 收口为 `success/partial_success/failed`。
- reconcile handler 已注册，但没有周期 scheduler 投递。
- 缺少多来源 `discovery_observation` 与关系端点 natural key/client_ref 入库链路。
- Baiyan 没有共享 Capability/Job Core、持久 Job Store、Engine HTTP Facade、callback sender 或新 MCP Server。

## 已冻结的架构决策

1. ASM 生产调度始终使用 Engine HTTP API + HMAC Webhook；MCP 不能替代该主链路。
2. ASM 是项目、Scope、RBAC、审计、任务状态和风险的事实来源；Baiyan 不写 ASM 数据库。
3. Engine Contract v1 的所有 ID（`run_id/project_id/scope_id`）统一为 JSON `uint64`；`Idempotency-Key` 使用十进制 `run_id` 字符串。
4. callback `result_count` 表示本批增量；TaskRun 累加必须依赖首次成功处理该 seq，不能在重复 callback 时累加。
5. `discovery_callback` 作为持久 inbox：先可靠保存受限 payload，再异步入队；worker 任务只携带 callback 主键/复合键。
6. 同一 `(project_id, run_id, seq)`：同 hash 返回幂等成功；不同 hash 返回 409、写审计，禁止覆盖。
7. final 终态只能在该 run 所有已接收 seq 都成功 ingest 后提交。
8. 第一条 E2E 仅开放授权根域的被动子域发现与 DNS enrich；禁止 masscan、目录扫描、AXFR、alterx、ESD、证书关联 IP 追扫。
9. 企业/ICP 结果仅是 `unverified` 候选，不自动创建 Scope 或主动扫描目标。
10. MCP 当前不交付；不得引入 SDK、进程入口或部署配置。后续恢复必须另开目标并重新审批。

## 执行顺序

| 顺序 | 任务 | 模块 | 状态 | 依赖 |
| --- | --- | --- | --- | --- |
| 1 | EXT-00 Engine Contract v1 冻结 | contract/docs | [x] | 无 |
| 2 | EXT-01 Discovery 受保护管理 API | discovery/auth | [x] | EXT-00 |
| 3 | EXT-02 Dispatch 队列、可信 callback URL 与配置统一 | discovery/worker/platform | [x] | EXT-00、EXT-01 |
| 4 | EXT-03 Callback v1 严格入口与持久 inbox | discovery/platform | [x] | EXT-00 |
| 5 | EXT-04 Final 状态收口与周期 reconcile | discovery/worker | [x] | EXT-02、EXT-03 |
| 6 | EXT-05 Observation 数据模型与 repository | discovery | [x] | EXT-00 |
| 7 | EXT-06 v1 结果、关系与事件事务化入库 | discovery/asset/exposure | [x] | EXT-03、EXT-05 |
| 8 | EXT-07 Baiyan Job Core 与 Engine HTTP 骨架 | engines/baiyan | [x] | EXT-00 |
| 9 | EXT-08 Baiyan 被动发现垂直切片 | engines/baiyan | [x] | EXT-07 |
| 10 | EXT-09 ASM + Baiyan E2E | integration | [x] | EXT-04、EXT-06、EXT-08 |
| 11 | EXT-10 MCP 被动/作业查询入口 | engines/baiyan | [—] 用户决定暂缓（2026-07-14） | 新目标与重新审批 |
| 12 | EXT-11 主动能力分阶段开放 | engines/baiyan/discovery | [!] 安全门 | EXT-09、专项审批 |

---

# Coding Agent Task — EXT-00

## Background

当前项目是 ASM 暴露面风险管理平台。本任务属于：`discovery contract`。现有代码已经有 EngineAdapter 草案，但请求、callback 和错误结构尚未形成独立、版本化、机器可校验的契约。

## Objective

创建并冻结 `Engine Contract v1` OpenAPI，作为 ASM 与 Baiyan 后续编码的唯一协议来源。

## Scope

允许修改：

- `api/engine-openapi.yaml`（新增）
- `docs/Baiyan外部引擎接入与MCP改造计划.md`（仅在发现契约矛盾时做最小同步）
- OpenAPI lint/contract test 所需的现有测试或脚本目录

禁止修改：

- `internal/`、`cmd/`、`migrations/`、`web/`
- `engines/baiyan/` 业务实现
- 禁止引入生产依赖、真实地址、Token、样例客户资产

## Requirements

1. 定义 `POST /scan`、`GET /scan/{engine_job_id}`、`POST /scan/{engine_job_id}/cancel`。
2. `POST /scan` 必须要求 Bearer token 与 `Idempotency-Key`，成功只返回 `202 {engine_job_id}`。
3. Scan request 固定字段：`schema_version=1.0`、uint64 `run_id/project_id/scope_id`、`job_type`、`targets`、`rate_limit`、`concurrency`、`timeout_seconds`、`callback_url`、白名单 `options`。
4. 第一阶段 profile 只定义 `subdomain_passive` 与 `resolve`；主动 profile 可以在 enum 中保留但标注 disabled-by-default，不得提供任意命令/路径字段。
5. 定义 callback DTO：`schema_version/run_id/seq/phase/status/result_count/observed_at/assets/relations/exposures/provider_errors/error_summary`。
6. `phase` 使用 `started/progress/completed/failed`；`completed/failed` 是 final phase。
7. 每条 asset/relation/exposure 必须有稳定 `client_ref` 或 natural key、`source/provider`、`observed_at`、`confidence`、`active_probe`、`evidence_hash`，`evidence_ref` 可选。
8. relation 端点只能引用 `client_ref/natural_key`，不能接受 ASM 数据库 ID。
9. 明确 `result_count` 是本批增量；明确最大 body、每批最大 items、字符串最大长度和时间格式。
10. 定义统一错误响应和 400/401/404/409/422/429/500/503。

## Data / API Contract

- Request：以上 v1 schema，`additionalProperties: false`。
- Response：Engine API 返回引擎原生 envelope；callback 响应沿用 ASM `{request_id,data}`。
- Error codes：至少 `INVALID_SCHEMA_VERSION`、`INVALID_PROFILE`、`IDEMPOTENCY_CONFLICT`、`JOB_NOT_FOUND`、`JOB_NOT_CANCELLABLE`、`RATE_LIMITED`、`ENGINE_UNAVAILABLE`。
- DB migration：无。

## Acceptance Criteria

- [x] OpenAPI 可被解析器加载，无重复/悬空 `$ref`。
- [x] 三个 Engine endpoint 和 callback payload 全部可机器校验。
- [x] ID 类型、phase、status、result_count 语义无歧义。
- [x] options 不允许任意 shell、文件路径或 credential 字段。
- [x] 示例只使用 `example.com` 和保留文档地址。

## Test Commands

请运行：

- 项目已有 OpenAPI lint/validation 命令；若没有，使用不新增生产依赖的解析方式验证 YAML，并说明方式。
- `git diff --check`

## Output Required

完成后回复：

1. 修改文件列表
2. 契约决策摘要
3. 验证结果
4. 兼容风险与待审点

## Completion Evidence

- 文件：`api/engine-openapi.yaml`。
- YAML/OpenAPI 基础解析：通过（OpenAPI 3.0.3、3 paths、68 个内部 `$ref` 全部可解析）。
- 严格 Schema 检查：通过（profile options 无命令/路径/凭据字段；callback `additionalProperties: false`；`result_count` 为本批增量）。
- `git diff --check -- api/engine-openapi.yaml`：通过。
- 迁移/权限/运行时影响：无；本检查点只冻结契约。

---

# Coding Agent Task — EXT-01

## Background

当前项目是 ASM 暴露面风险管理平台。本任务属于：`discovery/auth`。Scope、TaskTemplate、TaskRun 已有 service/repository，但没有受保护 HTTP 路由。

## Objective

挂载项目隔离、RBAC 完整的 Discovery 管理 API，并同步平台 OpenAPI。

## Scope

允许修改：

- `internal/discovery/*handler*.go` 及对应测试
- `cmd/api/main.go` 及对应测试
- `api/openapi.yaml`
- 仅在现有权限定义确实缺失时修改 auth/casbin seed

禁止修改：

- migration 与既有表结构
- EngineAdapter、callback ingest、Baiyan、前端
- 禁止重构 project/auth 全局机制

## Requirements

1. 提供项目级 Scope list/get/create/update/deactivate。
2. 提供 TaskTemplate list/get/create/update/enable/disable/delete。
3. 提供 TaskRun list/get/manual trigger/cancel；manual trigger 本任务只创建 pending run，队列接线由 EXT-02 完成。
4. 所有路由放在 JWT + password-changed 保护组。
5. 读操作要求 `scope:read` 或 `discovery:read`；写 Scope 要求 `scope:write`；触发/取消要求 `discovery:run`。
6. 每次调用先通过现有 `project.Service.Authorize` 做项目成员/全局角色校验；创建任务额外要求项目 active。
7. handler 只做 DTO、校验、权限和响应，不复制 service 业务逻辑。
8. 列表分页和排序使用白名单；错误映射遵循统一 envelope。

## Data / API Contract

- 路径前缀：`/api/v1/projects/{project_id}`。
- Response：`{request_id,data}`。
- Error codes：401、403、404、409、422；跨项目不得泄露资源存在性。
- DB migration：无。

## Acceptance Criteria

- [x] 未认证为 401，无权限为 403，跨项目访问被拒。
- [x] 停用/非 active 项目不能创建新 run。
- [x] Scope/Template/Run 的读取与变更 API 已同步 OpenAPI。
- [x] 变更操作继续由 service 写审计，不在 handler 重复写。

## Test Commands

- `go test ./internal/discovery ./cmd/api -race`
- `make lint`
- `make build`

## Output Required

按 `CLAUDE.md` §13 回复。

## Completion Evidence

- 新增 `internal/discovery/management_handler.go` 与 handler tests；在 `cmd/api/main.go` 的受保护组挂载。
- API：Scope list/get/create/update/deactivate；Template list/get/create/update/enable/delete；Run list/get/manual trigger/cancel，已同步 `api/openapi.yaml` v0.9.0。
- 权限：project access + `scope:read/scope:write/discovery:read/discovery:run` 双层、fail-closed 校验；tenant/org 从项目派生；inactive 项目 trigger 返回 409。
- 自动化证据：权限拒绝、跨项目、项目元数据派生、template/run 创建、分页和排序白名单测试。
- `go test ./internal/discovery ./cmd/api -race`：通过。
- `make lint`：0 issues；`make build`：通过。
- platform OpenAPI：YAML 可解析，345 个内部 `$ref` 全部存在；`git diff --check`：通过。
- DB migration：无。

---

# Coding Agent Task — EXT-02

## Background

当前项目是 ASM 暴露面风险管理平台。本任务属于：`discovery/worker/platform`。已有同步 `DispatchTaskRun`，但没有 asynq producer/consumer，也没有可信 callback URL builder。

## Objective

把 pending TaskRun 可靠投递给外部引擎，并统一 discovery 配置。

## Scope

允许修改：

- `internal/discovery/enqueue.go`、新增 dispatch handler/测试
- `internal/discovery/service.go` 必要的最小接线
- `cmd/api/main.go`、`cmd/worker/main.go` 及测试
- `.env.example`、`docker-compose.yml`

禁止修改：

- callback payload/入库模型（EXT-03/06）
- Baiyan 实现、风险/工单/前端
- 禁止接收用户提供的 callback URL

## Requirements

1. 新增 `dispatch_task_run` asynq task，payload 只含 `project_id/run_id/actor_id`。
2. manual trigger 创建 run 成功后入队；同一 run 重复入队/重试不能重复起引擎任务。
3. worker consumer 调用现有 `DispatchTaskRun`；仅 pending run 可下发。
4. callback URL 只能由 `DISCOVERY_CALLBACK_BASE_URL` 生成，固定路径 `/api/v1/discovery/callback`，附 `project_id/run_id`，seq 由引擎回调时附加。
5. 统一配置：`DISCOVERY_ENGINE_BASE_URL`、`DISCOVERY_ENGINE_TOKEN`、`DISCOVERY_CALLBACK_SECRET`、`DISCOVERY_CALLBACK_BASE_URL`。
6. API 缺 callback secret/base URL 时 callback/trigger 必须 fail closed；worker 缺 engine URL 时 dispatch task 返回可重试配置错误，不伪造成功。
7. HTTP client 设置总超时、响应体上限并校验状态响应 enum；不得使用无限制 `http.DefaultClient`。
8. 审计记录 run dispatch success/failure，但不记录 token/完整 payload。

## Data / API Contract

- Asynq task：`dispatch_task_run`。
- Callback URL：配置 origin + `/api/v1/discovery/callback?project_id={id}&run_id={id}`。
- Error codes：配置缺失、不可下发、引擎不可用分别可定位。
- DB migration：无。

## Acceptance Criteria

- [x] 创建 run 后产生 dispatch task，worker 能下发并记录 engine_job_id。
- [x] 重试使用相同 `Idempotency-Key`，不重复起 job。
- [x] callback URL 不可由 API 调用者控制。
- [x] `.env.example` 与 compose 不再使用旧 `ENGINE_*` 名称。
- [x] token、secret 不进入日志/审计。

## Test Commands

- `go test ./internal/discovery ./cmd/api ./cmd/worker -race`
- `make test`
- `make lint`
- `make build`

## Output Required

按 `CLAUDE.md` §13 回复。

## Completion Evidence

- 新增 `dispatch_task_run`、稳定 TaskID `dispatch:{project}:{run}`、identifier-only payload、API producer 与 worker consumer。
- manual trigger 改为 create+enqueue；Redis 入队失败时 run 事务审计后收口 cancelled，不留下孤儿 pending；pending/running cancel 幂等。
- callback URL 只能由 `DISCOVERY_CALLBACK_BASE_URL` 生成固定 `/api/v1/discovery/callback?project_id=...&run_id=...`。
- HTTP EngineAdapter 对齐 v1 数字 ID/schema_version/project/scope，要求 Bearer token，默认 30s client timeout、1 MiB 响应上限、未知字段与非法状态拒绝。
- API/worker 均 fail closed；API 仅用可信 engine 配置执行 cancel，worker 缺配置时 dispatch task 返回可重试错误。
- `.env.example`/compose 已统一四个 `DISCOVERY_*` 名称；`docker compose config --quiet` 通过（仅提示既有 version 字段 obsolete）。
- `go test ./internal/discovery ./cmd/api ./cmd/worker -race`：通过。
- `make test`：通过；`make lint`：0 issues；`make build`：通过。
- platform OpenAPI 348 个内部 `$ref` 完整；旧 `ENGINE_*` 精确键检查与 `git diff --check`：通过。
- DB migration：无。

---

# Coding Agent Task — EXT-03

## Background

当前项目是 ASM 暴露面风险管理平台。本任务属于：`discovery/platform`。现有 callback ledger 不保存 payload，插入后 Redis 入队失败会形成不可恢复丢失。

## Objective

将 callback 改为严格 v1、有限大小、可恢复的持久 inbox。

## Scope

允许修改：

- `internal/discovery/callback.go`、`handler.go`、`enqueue.go`、repository/model/query 与测试
- 新增下一序号 migration（不得改写 000009）
- `api/openapi.yaml` callback 部分
- `cmd/api/main.go` 必要接线

禁止修改：

- asset/exposure/relations 业务入库（EXT-06）
- TaskRun final 状态（EXT-04）
- Baiyan、前端

## Requirements

1. handler 在读取前使用 `http.MaxBytesReader` 或等价机制限制 body；超限返回 413。
2. v1 DTO 使用 `json.Decoder.DisallowUnknownFields`，校验 `schema_version=1.0`、phase/status、时间、数组数量、字段长度和总 items。
3. HMAC 仍对 `timestamp + raw_body` 验证，先验签再解析；保持 5 分钟窗口。
4. migration 为 `discovery_callback` 增加受限 `payload_json`、`payload_size`、`ingest_status`、`ingest_attempt`、`ingest_error`、`processed_at` 及 pending 索引；提供 down。
5. 插入 callback、保存 payload、更新 run 的 last_callback_at 必须同事务提交。
6. worker task 只携带 callback ID 或 `(project_id,run_id,seq)`，不能再复制 raw body到 Redis。
7. 同 seq 同 hash：返回 duplicate，并在仍 pending 时安全补投；同 seq 不同 hash：409 + 审计。
8. 提供 pending inbox recovery 查询/投递入口；Redis 短暂故障不能丢结果。
9. 日志和错误不得输出 raw payload、HMAC secret 或 evidence 原文。

## Data / API Contract

- Request：严格遵循 `api/engine-openapi.yaml` CallbackBatchV1。
- Response：成功仍为统一 envelope，包含 duplicate 状态。
- Error codes：新增 `CALLBACK_TOO_LARGE`、`CALLBACK_SCHEMA_UNSUPPORTED`、`CALLBACK_PAYLOAD_CONFLICT`。
- DB migration：新增 migration，向后兼容已有记录，down 明确删除新增列/索引。

## Acceptance Criteria

- [x] 超大 body、未知字段、错误版本、数组超限均拒绝。
- [x] DB 成功而 Redis 失败后可通过重复 callback 或 recovery 恢复。
- [x] payload conflict 不覆盖旧记录。
- [x] transaction 回滚不留下半状态。
- [x] migration 在 MySQL 8 up/down/re-up 通过。

## Test Commands

- `go test ./internal/discovery ./cmd/api -race`
- `make migrate-up` / `make migrate-down`（隔离测试库）
- `make sqlc`
- `make test`
- `make lint`
- `make build`

## Output Required

按 `CLAUDE.md` §13 回复，必须单列迁移与恢复语义。

## Completion Evidence

- callback HTTP 入口在读取前使用 4 MiB `http.MaxBytesReader`，超限返回 413/`CALLBACK_TOO_LARGE`；HMAC 仍先于 JSON 解析并保持 5 分钟防重放窗口。
- v1 DTO 严格拒绝未知字段、缺失/空必填数组、非 `1.0` schema、非法 phase/status、超限数组/字符串、count 不一致、非法 evidence hash 与 `active_probe=true`。
- `000024_discovery_callback_inbox` 将 payload、大小、schema/observed_at、ingest 状态/次数/错误/处理时间持久化并建立 pending 索引和 CHECK；同步 retention archive，历史 ledger 安全回填 processed，避免升级后误重放。
- callback insert + payload + `last_callback_at` 同事务；sqlmock 已证明 run 更新失败会 rollback 且不入队。
- Redis 任务只含 `(project_id,run_id,seq)`，稳定 TaskID `ingest:{project}:{run}:{seq}`；worker 按标识从 MySQL inbox 读取 payload，队列中无 raw body。
- 同 seq 同 hash 在 pending 状态补投；不同 hash 返回 409/`CALLBACK_PAYLOAD_CONFLICT` 且不覆盖；Redis 故障后重复 callback 或 `RecoverPendingCallbacks` 可恢复。
- MySQL 8 专用库完成 000001–000024 升级、EXT-03 down/re-up 和列/CHECK 检查；测试库已清理。既有 000023 需 mysql client `utf8mb4`（默认 latin1 会触发其既有 COLLATE 错误），不属于本检查点改写范围。
- `make sqlc`：通过；两份 OpenAPI 共 361/68 个内部 `$ref` 完整；`go test ./internal/discovery ./internal/platform/retention ./cmd/api ./cmd/worker -race`：通过。
- `make test`：通过；`make lint`：0 issues；`make build`：通过；`git diff --check`：通过。
- 2026-07-14 重新使用隔离 MySQL 8 硬断言验证：000001–000025 全量 up，000025/000024 down，再按 000024/000025 re-up；表、三列 callback inbox 字段及六列 observation 唯一索引均符合预期。

---

# Coding Agent Task — EXT-04

## Background

当前项目是 ASM 暴露面风险管理平台。本任务属于：`discovery/worker`。现有 reconcile handler 未周期调度，final callback 也不会在 ingest 完成后可靠收口 run。

## Objective

实现 TaskRun 终态收口、周期 inbox recovery 与 timeout reconcile。

## Scope

允许修改：

- `internal/discovery/*worker*.go`、service/repository/query 的最小增量及测试
- `cmd/worker/main.go` 及测试

禁止修改：

- callback v1 字段定义、observation/关系模型、Baiyan、前端
- 禁止把 final 状态提前写在 HTTP callback handler

## Requirements

1. worker 成功处理 callback 后原子标记 inbox processed。
2. final callback 仅在该 run 所有已接收 seq 均 processed 后收口。
3. final `success/partial_success/failed/cancelled` 映射到合法 TaskRun 状态；非法组合拒绝并审计。
4. `result_count` 只在 seq 首次 processed 时累加，重复 worker 不重复计数。
5. worker 启动真实 asynq scheduler，周期投递 pending inbox recovery 与 timed-out reconcile。
6. reconcile 对 engine running 保持运行；对 success/partial/failed/cancelled 做合法收口；网络错误按上限重试。
7. timeout 路径尝试取消 engine，取消失败要记录但不能阻止本地超时收口。
8. shutdown 时同时优雅停止 server 与 scheduler。

## Acceptance Criteria

- [x] progress callback 不提前终结 run。
- [x] final 到达但前序 seq 未 ingest 时不终结，补齐后正确终结。
- [x] 重复 task 不重复累加 result_count。
- [x] scheduler 在测试中可观察到注册的周期任务。
- [x] timeout/reconcile/partial_success/cancelled 都有测试。

## Test Commands

- `go test ./internal/discovery ./cmd/worker -race`
- `make test`
- `make lint`
- `make build`

## Output Required

按 `CLAUDE.md` §13 回复。

## Completion Evidence

- worker 对 inbox 执行 pending/failed/stale-processing claim；成功处理后在同一事务中标记 processed、首次累加该 seq 的 `result_count`、检查完整序列并按 final callback 收口 TaskRun。
- final seq 已 ingest、前序 seq 未 ingest 时保持 running；前序补齐后收口 success。重复 complete 不再次累加；progress 不提前终结。
- final 映射覆盖 success/partial_success/failed/cancelled；非法 final 组合由严格 HTTP DTO 拒绝并审计，非连续/中途 final 序列由 worker 状态机拒绝。
- 新增 `recover_discovery_callbacks` handler；pending、可重试 failed 与超过 5 分钟的 processing claim 可由持久 inbox 恢复，最多 10 次 claim。
- worker 启动真实 asynq Scheduler：callback recovery `@every 30s`、timeout reconcile `@every 1m`，两者 `MaxRetry(5)` 且有任务超时；注册内容通过 fake registrar 自动化测试可观察。
- engine running 保持本地 running；success/partial/failed/cancelled 合法映射。网络错误由 handler 返回给 asynq 上限重试；timeout 会尝试 cancel，cancel 失败记录为脱敏 error summary 且不阻止本地 failed 收口。
- shutdown 同时停止 scheduler 与 server；无 raw callback、engine token 或 cancel 原始错误进入日志/审计。
- `make sqlc`、`git diff --check`：通过；`go test ./internal/discovery ./cmd/worker -race`：通过。
- `make test`：通过；`make lint`：0 issues；`make build`：通过。

---

# Coding Agent Task — EXT-05

## Background

当前项目是 ASM 暴露面风险管理平台。本任务属于：`discovery`。asset 主表单一 `source` 无法保存同一事实的多 provider 证据。

## Objective

新增 `discovery_observation` 数据模型与项目隔离 repository，不接入主表写入。

## Scope

允许修改：

- 新增下一序号 migration
- `internal/discovery/model.go`、repository/query 与测试

禁止修改：

- asset/exposure/risk 表结构与 service
- callback handler、Baiyan、前端

## Requirements

1. 字段包含 tenant/org/project、run/seq、kind、natural_key、client_ref、provider、capability、observed_at、confidence、active_probe、evidence_hash/ref、normalized_json、ingest_status/error、审计时间。
2. 唯一键至少覆盖 `(project_id,run_id,kind,natural_key,provider)`；natural_key/provider 必须规范化并限制长度。
3. 查询必须强制 project_id；支持按 run/seq 和 natural key 追溯。
4. 不保存 token/cookie/完整响应体；`normalized_json` 有大小限制。
5. migration 提供 down，并为 run 追溯与生命周期比较建立必要索引。

## Acceptance Criteria

- [x] 多 provider 同一 asset 可保留多条 observation。
- [x] 同 provider 同 natural key 重试幂等。
- [x] 跨项目读取不到记录。
- [x] MySQL 8 up/down/re-up 通过。

## Test Commands

- `make sqlc`
- `go test ./internal/discovery -race`
- `make migrate-up` / `make migrate-down`（隔离测试库）
- `make lint`
- `make build`

## Output Required

按 `CLAUDE.md` §13 回复。

## Completion Evidence

- 新增 `000025_create_discovery_observation` up/down 与 sqlc cumulative schema；字段覆盖 tenant/org/project/run/seq、kind/natural_key/client_ref、provider/capability、时间/置信度/active_probe、evidence hash/ref、受限 normalized JSON、ingest 状态/错误和审计时间。
- 唯一键 `(project_id,run_id,kind,natural_key,provider,deleted_at)` 保证同 provider 重试幂等、不同 provider 事实共存；复合 FK 指向同项目 TaskRun。
- run/seq 追溯索引、生命周期比较索引和对应 repository 查询均强制 `project_id`；跨项目 ID 读取测试返回 not found。
- repository 统一 trim/lower 规范化 natural key/provider/capability，校验标识符、长度、时间、置信度、evidence SHA-256、状态和 UTF-8/NUL。
- `normalized_json` 必须是对象且不超过 64 KiB；递归拒绝 token/cookie/authorization/password/secret/api_key 等敏感字段，不保存原始响应体。
- sqlmock 覆盖 upsert 后 project-scoped read；fake repository 测试证明同 provider 同 ID、两 provider 两条 observation。
- MySQL 8 专用库完成 000001–000025、EXT-05 down/re-up；确认唯一键、run/lifecycle 索引、复合 FK 与四个 CHECK，测试库已清理。
- `make sqlc`：通过；`go test ./internal/discovery -race`：通过；`make lint`：0 issues；`make build`、`git diff --check`：通过。
- 2026-07-14 与 EXT-03 共用隔离 MySQL 8 重新执行 000025 down/re-up，并以实际 `uk_discovery_observation_fact` 六个索引列做硬断言，通过后清理测试环境。

---

# Coding Agent Task — EXT-06

## Background

当前项目是 ASM 暴露面风险管理平台。本任务属于：`discovery/asset/exposure`。v1 callback 需要把 observation、资产、关系、暴露面和变化事件可靠关联。

## Objective

实现 v1 结果的幂等、项目隔离、可追溯入库，包括 `domain -> subdomain -> ip` 关系。

## Scope

允许修改：

- `internal/discovery/worker.go` 及测试
- `internal/discovery` ingest service/repository/query
- `internal/asset`、`internal/exposure` 中为 tx-scoped upsert/关系写入所需的最小接口与测试
- 如可靠事件确需字段/表，新增独立 migration；不得改旧 migration

禁止修改：

- risk scoring/state machine、ticket、report、前端
- 不实现任何网络探测

## Requirements

1. 先保存 observation，再按 natural key 幂等 upsert asset/exposure。
2. relation 端点由当前批次 `client_ref` 或 natural key 解析；不得接受数据库 ID。
3. 关系两端先 upsert，再校验同 tenant/org/project，最后写 `asset_relation`。
4. observation、主表 upsert、relation、change_event 必须使用同一事务，或使用可恢复 outbox；禁止半成功永久丢事件。
5. 多来源只更新主资产的主来源策略，不覆盖/删除 observation。
6. 同 seq 重试不重复资产/关系/事件；无关键变化只更新 last_seen。
7. completed 后基于本次 observation 集合驱动 hit/miss；只比较本 run 对应 capability 管辖的资产，不能误伤手工导入资产。
8. evidence 只保存 hash/ref 和必要摘要。

## Acceptance Criteria

- [x] `example.com -> api.example.com -> 192.0.2.10` 图谱正确且重复回调不重复。
- [x] 两 provider 命中同子域：一条 asset、两条 observation。
- [x] 重复无变化不产 change_event。
- [x] 事务任一步失败不会留下不可恢复半状态。
- [x] 跨项目 relation 被 service 和复合 FK 双重拒绝。

## Test Commands

- `go test ./internal/discovery ./internal/asset ./internal/exposure -race`
- `make test`
- `make lint`
- `make build`

## Output Required

按 `CLAUDE.md` §13 回复，必须说明事务边界。

## Completion Evidence

- 新增 v1 materializer：每个 callback batch 使用单一 `sql.Tx`，严格按 observation observed → asset/exposure/relation upsert → change_event → observation materialized 的顺序；任一步失败 rollback 整批。
- worker 生产接线改为 `CallbackFactIngester`；materialize 失败将 inbox 标记 failed，成功后才进入 EXT-04 的 processed/count/final 事务。
- asset facts 先统一 Normalize 并按 project upsert；reference map 只接受当前批次 `client_ref`/natural key，不接受数据库 ID。relation 两端必须已由本批资产事实 upsert，再经过 asset service tenant/org/project 校验和复合 FK。
- v1 `contains/resolves_to` 原样落图；`cname_to`/`presents_certificate` 以 observation 保留原语义并映射到既有 `references/cert_binding` 主图类型，避免破坏已锁定 DB enum。
- provider 证据先各自保存 observation；两个 provider 命中同子域时主 asset 一条、observation 两条。evidence 只保存 hash/ref 与受限规范化事实，不保存原始响应。
- 主表来源策略改为只允许空/`discovery` 被 discovery 更新，手工来源不会被覆盖；confidence 取最大值，已有 display name 保留。asset/relation 写入支持事实 `observed_at`。
- callback 重放再次 materialize 时 observation/asset/relation 保持幂等；关键字段无变化只刷新 last_seen，不重复 change_event。
- final success/partial 时按 run+capability observation 集合执行生命周期；success 才产生 miss，partial 只处理 hit；仅 `source=discovery` 且历史上受该 capability 管辖的资产参与，手工资产不受影响，阈值由 `ASSET_MISS_THRESHOLD` 注入。
- 隔离 MySQL 8 integration 测试验证 `example.com → api.example.com → 192.0.2.10`、双 provider、一条主资产、两条关系、六条 observation、重复无事件、错误 relation 整批 rollback、final success 与 hit/miss/manual 隔离；测试库和临时用户已清理。
- 既有 asset relation 测试与复合 FK继续覆盖跨项目双重拒绝；全量 `make test` 通过。
- `make sqlc`：通过；`go test ./internal/discovery ./internal/asset ./internal/exposure -race`：通过；integration tag 测试通过；`make lint`：0 issues；`make build`、`git diff --check`：通过。
- 2026-07-14 在全量迁移后的隔离 MySQL 8 重新运行 `TestV1IngestGraphIdempotencyAndRollback`（integration tag + race），图谱、双 provider、重放无事件、错误关系整批 rollback 与生命周期断言全部通过。

---

# Coding Agent Task — EXT-07

## Background

当前项目是 ASM 暴露面风险管理平台。本任务属于：`engines/baiyan`。Baiyan 当前 CLI 直接串联扫描步骤并使用共享文件/checkpoint，不适合并发异步作业。

## Objective

建立不执行真实扫描的 Capability/Job Core、持久 Job Store 和 Engine HTTP Facade 骨架。

## Scope

允许修改：

- `engines/baiyan/cmd/` 新入口
- `engines/baiyan/internal/{contract,job,engine,capability}` 等清晰新包
- `engines/baiyan/go.mod` 仅在用户明确批准依赖后修改
- Baiyan 单元/契约测试与开发文档

禁止修改：

- ASM `internal/`、migration、前端
- 现有扫描实现的大规模重写
- 禁止启动 masscan/dirscan/observer_ward 或访问外网

## Requirements

1. CLI、HTTP、未来 MCP 必须调用同一 JobService/Capability registry。
2. Job 状态：pending/running/success/partial_success/failed/cancelled；状态机并发安全。
3. 同一 Idempotency-Key + 同请求 hash 返回同 job；同 key 不同 hash 返回 409。
4. 每 job 使用独立 workspace，路径由 engine 生成，禁止请求传文件路径。
5. Job Store 先定义接口；若无已批准数据库依赖，使用标准库实现可测试的原子文件 store（临时文件 + rename + 权限 0700/0600），不得偷偷加依赖。
6. `POST /scan` 异步返回 202；GET status；cancel 幂等并触发 context cancel。
7. HTTP 设置 header/body/read/write/idle timeout、并发上限、Bearer auth；错误不泄露路径/凭据。
8. profile registry 仅注册 no-op/test capability；真实 passive 能力留 EXT-08。

## Acceptance Criteria

- [x] HTTP contract 与 `api/engine-openapi.yaml` 一致。
- [x] 幂等冲突、取消、重启恢复、并发 job workspace 隔离有测试。
- [x] 网关无需 root，测试不执行任何外部二进制/网络请求。
- [x] `go test ./... -race` 在 `engines/baiyan` 通过。

## Test Commands

- `cd engines/baiyan && go test ./... -race`
- `cd engines/baiyan && go build ./cmd/...`
- `git diff --check`

## Output Required

按 `CLAUDE.md` §13 回复；额外列出 Job Store 崩溃恢复语义。

## Completion Evidence

- 新增完全独立的 `cmd/baiyan-engine`、`internal/{contract,job,engine,capability}`；新入口依赖图不包含 legacy `internal/baiyan` 或 `os/exec`，不加载/调用 active 二进制。
- Engine HTTP Facade 以 stdlib 实现 `POST /scan`、`GET /scan/{id}`、`POST /scan/{id}/cancel`；Bearer、契约一致的 2 MiB body、严格未知字段、数字 ID、Idempotency-Key、callback 固定 origin/path/project/run 和 options allowlist 均 fail closed。
- 只注册 `passive_intel/subdomain_passive` 与 `dns/resolve`；port_probe/web_probe/fingerprint 和命令/凭据/路径类 options 自动拒绝。
- Job ID 固定为 `job-{run_id}`；同 key+同 request hash 幂等，同 run 不同请求 409。队列有界，worker timeout/cancel 传播到 executor。
- File Job Store 使用 0700 目录、0600 临时文件、fsync+atomic rename；启动将 persisted queued/running 重置 queued 并重放，terminal 不重放。恢复/idempotency/cancel 有 race 测试。
- `ENGINE.md` 与 `.env.engine.example` 记录配置、安全边界和崩溃恢复；未新增任何依赖，`go.mod/go.sum` 未改。
- `go test ./... -race`：通过（按既有 `build.sh` 临时 staging legacy embed lib，完成后已清理）；`go build ./cmd/...`：通过。
- 新包定向 `go vet`：通过；`git diff --check`：通过。
- 新增并发 Job 状态隔离测试：两个 worker 同时运行 `job-10/job-11`，任一任务先完成不会改变另一任务状态或串写结果。
- 契约审计修正 Engine request body 从实现 1 MiB 漂移到冻结契约 2 MiB，并增加超过 2 MiB 返回 413 的 HTTP 测试。
- 为使 legacy 全量测试与其断言一致，仅把 `scan_policy_test` 明确固定为 `FastScan=true`；未修改 legacy 扫描实现或默认策略。

---

# Coding Agent Task — EXT-08

## Background

当前项目是 ASM 暴露面风险管理平台。本任务属于：`engines/baiyan`。Job Core 已建立，需要第一条低风险被动发现能力。

## Objective

实现 `subdomain_passive` + `resolve` 垂直切片，并按 v1 schema 分批 HMAC callback。

## Scope

允许修改：

- `engines/baiyan/internal/capability`、provider adapter、callback sender、job worker 与测试
- 复用 `engines/baiyan/internal/baiyan` 中可安全抽取的被动子域/DNS逻辑

禁止修改：

- ASM 代码
- masscan、HTTP 探活、指纹、目录、alterx/ESD/AXFR、证书关联 IP 追扫
- 企业/ICP 候选自动授权

## Requirements

1. 只接受 `domain` target，必须是已下发根域或其合法子域；拒绝 IP/CIDR/URL。
2. provider 凭据只从环境/credential ref 读取，不接受 request options 传密钥。
3. provider adapter 设置 timeout、结果上限、并发/速率预算；单 provider 失败产生 provider_errors，允许 partial_success。
4. DNS A/AAAA/CNAME 结构化输出；解析 IP 只作为 observation/asset relation，不自动继续端口/Web 扫描。
5. callback seq 单调递增、批次有固定上限、result_count 为本批增量；final 只在前序 callback 获得 2xx 后发送。
6. callback 重试使用指数退避上限，同 seq payload/hash 不变。
7. HMAC 为 `sha256(secret, timestamp + raw_body)`；日志不含 secret/raw response。
8. cancel/timeout 必须向所有 provider goroutine 传播 context。

## Acceptance Criteria

- [x] mock provider E2E 可产生 domain/subdomain/ip 与 contains/resolves_to。
- [x] provider partial failure、callback 重试、取消、超时有测试。
- [x] 测试证明不会调用主动扫描二进制。
- [x] 无授权外扩、无自动追扫解析 IP。

## Test Commands

- `cd engines/baiyan && go test ./... -race`
- `cd engines/baiyan && go build ./cmd/...`
- `git diff --check`

## Output Required

按 `CLAUDE.md` §13 回复。

## Completion Evidence

- `PassiveExecutor` 只接受 Engine HTTP 已验证的 domain/subdomain 被动 profile；provider 候选再次规范化并限制在授权根域，`outside.invalid` 测试证明越界结果被丢弃。
- provider 通过受信环境配置的 bounded HTTP adapter（15s client、每调用 context timeout、1 MiB strict JSON、结果上限、Bearer 仅来自 env）；request options 不能传凭据。
- DNS enrich 使用 Go resolver、每 host timeout、并发上限 50、目标上限 500；只生成 A/AAAA IP 与授权范围内 CNAME，不触发端口/Web/指纹追扫。
- 结构化输出包含 root/subdomain/IP asset 和 contains/resolves_to/cname_to relation；所有事实带 source/provider/observed_at/confidence、`active_probe=false`、SHA-256 evidence hash/ref。
- callback started/progress/final seq 单调；每批最多 500 facts，`result_count` 等于本批事实数；每批 2xx 后才继续，最终 callback 只在前序成功后发送。
- callback sender 固定允许 origin，4 MiB 上限，HMAC `sha256(timestamp+raw_body)`，指数退避上限；重试测试证明同 seq raw body 不变。
- provider 部分失败产生脱敏 `provider_errors` + partial_success；取消传播到 provider，job timeout/cancel 由 context 统一传播。
- mock provider+resolver 垂直切片生成 `example.com → api.example.com → 192.0.2.10`；越界、partial、callback retry、取消均有自动化测试。
- 请求的 passive source 未配置时不再静默 success，而是产生 `PROVIDER_NOT_CONFIGURED` 与 `partial_success`；`dns/resolve` 严格按 A/AAAA/CNAME `record_types` 过滤，解析出的 IP 仅作为事实，不触发后续扫描。
- 新 engine 依赖/源码扫描不含 masscan、dirscan、observer_ward、alterx、ESD、AXFR 或 `os/exec`；全模块 race/build 证据同 EXT-07。

---

# Coding Agent Task — EXT-09

## Background

当前项目是 ASM 暴露面风险管理平台。本任务属于：`integration`。

## Objective

在完全 mock/保留文档目标下验证 ASM → Baiyan → callback → observation/asset/relation → TaskRun 终态。

## Scope

允许修改：

- Docker Compose 的开发 profile、测试配置、integration/E2E 测试
- 必要的 README/运行说明

禁止修改：

- 新业务能力、生产密钥、真实资产、主动扫描

## Requirements

1. 使用 MySQL 8、Redis、ASM api/worker、Baiyan engine。
2. 覆盖提交→202→running→多批 callback→ingest→success。
3. 覆盖重复提交、同 seq 重复/冲突、Redis 短故障恢复、引擎重启、取消、超时、partial_success。
4. 所有目标使用 `example.com`、`.invalid`、RFC 5737/3849 文档地址；provider 使用本地 mock。
5. 断言资产/关系/observation/change_event/audit/task_run 可追溯到同一 run。

## Acceptance Criteria

- [x] E2E 可重复执行且不访问公网。
- [x] 无任何 masscan/目录/指纹进程启动。
- [x] 故障注入后无 callback 永久丢失、无重复主记录。

## Test Commands

- 执行项目新增的 E2E 命令
- `make test`
- `make lint`
- `make build`
- `cd engines/baiyan && go test ./... -race`

## Output Required

按 `CLAUDE.md` §13 回复，并附 E2E 状态流证据。

## Completion Evidence

- 新增 `docker-compose.e2e.yml` 与 `make e2e-passive`，使用独立 MySQL 8/Redis、真实 ASM api/worker、Baiyan engine 及本地 mock provider；目标仅使用 `example.com`、`.invalid` 和 RFC 5737 地址，无公网依赖。
- E2E 从真实 asynq dispatch 开始，验证 `202 -> running -> 多批 callback -> ingest -> success`，最终图为 `domain:example.com -> subdomain:api.example.com -> ip:192.0.2.10`。
- 成功证据：`make e2e-passive` 退出码 0；结果为 `assets=3`、`relations=2`、`observations=6`、`events=5`、`callbacks=3`、`audits=2`、`result_count=6`、`status=success`。
- 同一 `Idempotency-Key` 的引擎重复提交返回同一 job；terminal 后同 seq+同 raw payload 返回 duplicate，同 seq+不同 payload 返回 conflict，不覆盖 inbox 主记录。
- 组合环境现直接覆盖 `partial_success`、真实受保护 API 取消、超时 reconcile、Redis 停止/恢复和引擎 `SIGKILL` 重启；不再以分层单测替代 EXT-09 的故障 E2E 要求。Redis 场景证明 callback 先落 MySQL durable inbox，恢复后由 recovery worker 消费并最终 success。
- Baiyan callback checkpoint 与 Job 记录一起原子持久化：发送前保存 immutable pending batch，2xx 后推进 `last_callback_seq`；崩溃恢复跳过已确认 seq、原样重放未确认 batch。E2E 在 provider 阻塞期间 `SIGKILL` 引擎，重启后同一 run 无 payload conflict 并最终 success。
- E2E 启动后检查所有子进程命令行，拒绝 masscan、dirscan、observer_ward；Baiyan 新入口依赖扫描同时证明无 active scanner/外部命令依赖。
- P0 回调来源绑定已从单一共享密钥推进为有界 credential set：新 run 快照 active `callback_secret_ref`，旧/新身份可在轮换窗口并存，空 ref 历史 run 仅使用显式 legacy secret；未知身份、跨身份签名、重复 identity、超限或畸形 JSON 均拒绝。E2E 使用双身份密钥配置验证完整链路。
- 出站 provider/DNS 与 callback 均禁止跟随重定向，避免凭据跨目标转发；每个 job 共用可取消的 `rate_limit` 门，且与并发上限独立。
- `Dockerfile.engine` 与 `make test-baiyan-image` 验证网关镜像以 `10001:10001`、只读根文件系统、`cap_drop: ALL`、`no-new-privileges` 运行，仅 job store 可写。
- 2026-07-14 回归证据：`make e2e-passive`、`make test`、`make build`、`make lint` 均通过；临时 staging 既有 legacy embed 资源后，Baiyan `go test ./... -race`、`go vet ./...`、`go build ./cmd/...` 全模块通过并已清理 staging。

---

# EXT-10 — MCP 被动/作业查询入口（已取消/暂缓）

## Background

当前项目是 ASM 暴露面风险管理平台。本任务属于：`engines/baiyan MCP`。

## Decision Record（2026-07-14）

- 用户不同意 MCP 接入提案，并要求先取消 MCP。
- 当前 Goal 在 EXT-09 结束；EXT-10 不编码、不验收，也不作为外部引擎交付的阻塞项。
- 不引入 MCP SDK，不升级 Baiyan Go 版本，不创建 `cmd/baiyan-mcp`，不增加 MCP transport、配置或部署面。
- ASM 与 Baiyan 的生产集成继续只使用 Engine HTTP API + HMAC Webhook。
- 后续如恢复 MCP，必须另开 Goal，并基于届时的 SDK 版本、License、安全修复、授权上下文和 transport 重新评审；本节不构成预批准。

## Acceptance Criteria

- [—] 暂缓，不适用于当前 Goal：MCP 与 HTTP 同请求语义一致。
- [—] 暂缓，不适用于当前 Goal：无授权主动 Tool 不存在或明确拒绝。
- [—] 暂缓，不适用于当前 Goal：Tool schema、分页、取消、错误映射有自动化测试。
- [—] 已通过不引入 MCP 依赖、入口或部署配置保持 Engine HTTP 独立。

---

# Coding Agent Task — EXT-11（安全门，未审批前禁止编码）

## Background

当前项目是 ASM 暴露面风险管理平台。本任务属于：`active discovery`。

## Objective

按独立任务逐步开放 `web_ports` → `http_probe` → `observer_ward`；每一步单独设计、审批、实现和审查。

## Security Gate

以下条件未全部满足不得开始：Scope/危险地址双层校验、重定向与最终 IP 每跳校验、DNS rebinding 防护、速率/并发/端口/目标预算、非 root 网关、隔离 active worker、完整进程组取消、固定规则库版本、E2E 与回滚开关。

明确后置且默认禁用：full/custom ports、directory、alterx、ESD、AXFR、证书关联 IP 自动追扫。
