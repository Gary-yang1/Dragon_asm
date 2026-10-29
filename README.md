# ASM 暴露面风险管理平台

> 以资产为中心、以变化为驱动、以风险闭环为目标的攻击面管理（Attack Surface Management）平台。

ASM 持续管理企业互联网暴露面，覆盖项目授权、资产发现、暴露面识别、风险评估、工单处置和管理报表。探测与情报采集由外部引擎执行；平台负责**授权边界、任务编排、结果归一化、风险建模与闭环管理**。

## 核心能力

- **项目与授权范围**：项目工作区、成员权限、Scope 有效期、include/exclude、默认 Scope 与域名覆盖方式。
- **资产管理**：域名、子域名、IP、端口、服务、Web、证书等资产的导入、去重、生命周期和关系图谱。
- **发现编排**：任务模板、手动执行、异步调度、超时回收、状态对账和场景 Blueprint 预检/模板实例化。
- **双引擎路由**：Baiyan 承载被动情报、DNS 与企业主体情报；可选外部 AK/SK 引擎承载受控的端口、Web 和指纹发现。
- **可靠结果管道**：HMAC 回调、持久 inbox、幂等重放、多来源 observation、资产/关系/暴露面事务化入库。
- **风险管理**：规则匹配、可配置评分、状态流转、抑制、风险接受/误报复审和状态历史。
- **处置闭环**：工单分派、整改、复测、SLA、通知规则和审计记录。
- **报表运营**：资产与风险看板、变化趋势、修复效能和异步导出。
- **平台管理**：用户与固定角色权限、引擎配置摘要、健康检查和 Worker 运行状态。

## 当前状态

项目处于 **MVP 收敛与发布候选验证阶段**：

- 项目、资产、发现、暴露面、风险、工单、通知、报表和管理前端均已实现。
- Baiyan 被动发现链路已具备本地 mock E2E；Baiyan 不执行 masscan、目录扫描、PoC 或其他主动扫描。
- 主动引擎适配器和结果归一化已接入，但主动下发默认关闭；生产启用前仍应完成授权环境 E2E、取消契约和安全审查。
- Blueprint 当前支持只读预检和显式生成手动模板，不会自动运行，也不会根据发现结果扩大 Scope；多步骤运行时编排与周期执行仍属后续能力。
- 通知投递当前接入 SSRF 防护的 Webhook；邮件 transport 尚未提供。
- 根目录 `docker-compose.yml` 仅用于本地开发，不是生产部署清单。

## 技术栈

- **后端**：Go 1.22、Gin、sqlc、MySQL 8.0、Redis、asynq、Casbin。
- **前端**：React 18、TypeScript、Vite、Ant Design / ProComponents、ECharts、AntV G6、Vitest。
- **引擎**：独立 Baiyan Engine HTTP 服务；可选外部 AK/SK 主动引擎。
- **部署与测试**：Docker Compose、golang-migrate、Testing Library、MSW。

## 架构

```text
Browser
   │
   ▼
ASM API (Gin)
   ├── JWT / RBAC / 项目隔离 / 审计
   ├── Project / Asset / Discovery / Risk / Ticket / Report
   └── Engine callback ingress
            │
            ▼
       MySQL durable inbox ──► Redis / asynq ──► ASM Worker
                                                    ├── 任务下发与状态对账
                                                    ├── 结果归一化与风险规则
                                                    ├── 报表导出与通知
                                                    └── 数据归档

ASM Worker ── HTTP ──► Baiyan passive engine
           └─ AK/SK ─► optional active engine
```

### 进程职责

- `cmd/api`：HTTP API、认证鉴权、项目级权限、业务接口、引擎回调和 readiness。
- `cmd/worker`：asynq consumer/scheduler、引擎下发、callback ingest、状态对账、导出、通知和归档。
- `engines/baiyan/cmd/baiyan-engine`：隔离的被动发现 HTTP Facade，采用持久 Job Store 和有界执行器。
- `web`：项目工作区、资产、发现、风险、工单、报表及平台管理界面。

### 引擎边界

| 路由 | 任务类型 | 默认状态 | 说明 |
| --- | --- | --- | --- |
| Baiyan passive | `passive_intel`、`dns`、`org_intel` | 配置后可用 | 被动 Provider、DNS enrich 和企业主体候选；不会自动扩展授权范围。 |
| External active | `port_probe`、`web_probe`、`fingerprint` | **关闭** | 仅允许显式授权目标；Web 请求强制 `nopoc=true`。 |
| Disabled | `dirscan` 及其他未注册任务 | 拒绝 | 不支持的任务不会被误报为“扫描结果为空”。 |

主动发现由以下配置门控制，并采用安全默认值：

```text
DISCOVERY_ACTIVE_DISPATCH_ENABLED=false
DISCOVERY_ACTIVE_REQUIRE_APPROVAL=true
DISCOVERY_ACTIVE_REQUIRE_OWNERSHIP=true
```

## 目录结构

```text
api/                    # ASM 与 Engine OpenAPI 契约
cmd/api/                # API 进程入口
cmd/worker/             # Worker 进程入口
engines/baiyan/         # Baiyan 独立 Go module 与容器构建
integration/ext09/      # ASM + Baiyan 被动发现 E2E
internal/               # auth/project/asset/discovery/exposure/risk/ticket/report 等模块
migrations/             # golang-migrate 数据库迁移
scripts/                # 本地启动辅助脚本
web/                    # React 管理前端
```

## 本地开发

### 环境要求

- Go 1.22+
- Node.js 20+ 与 pnpm 9+
- Docker 与 Docker Compose
- `golang-migrate`（运行数据库迁移）
- `golangci-lint`（运行后端 lint）
- `sqlc`（仅在修改 schema/query 后重新生成代码）

### 1. 准备配置

```bash
cp .env.example .env
```

必须替换 `.env` 中的 JWT、callback、引擎和 Provider 示例值。`.env`、Token、Cookie、AK/SK、私钥及真实客户目标不得提交到仓库。

### 2. 启动基础设施并迁移数据库

```bash
docker compose up -d mysql redis

# 与 .env 中的数据库配置保持一致
export DB_DSN='asm:changeme@tcp(localhost:3306)/asm?parseTime=true&loc=UTC&charset=utf8mb4'
make migrate-up
```

### 3. 启动后端

使用 Docker Compose：

```bash
docker compose up --build api worker
```

或构建本地二进制：

```bash
make build
./bin/api
./bin/worker
```

存活与就绪端点：

```text
GET /healthz
GET /readyz
```

`/healthz` 只表示进程存活；`/readyz` 还会检查业务路由和数据库是否可用。

### 4. 启动前端

```bash
pnpm --dir web install --frozen-lockfile
pnpm --dir web dev
```

Vite 开发服务器默认监听 `http://localhost:5173`，API 默认监听 `http://localhost:8080`。

### 5. 可选：启动 Baiyan 被动引擎

先在 `.env` 中配置一致的 Engine Token、callback identity/HMAC secret、Provider，以及：

```text
DISCOVERY_PASSIVE_ENGINE_BASE_URL=http://baiyan-engine:9090
```

然后启动 opt-in profile：

```bash
docker compose --profile baiyan up --build baiyan-engine api worker
```

完整配置和恢复语义见 [`engines/baiyan/ENGINE.md`](engines/baiyan/ENGINE.md)，第三方工具来源与固定版本见 [`engines/baiyan/TOOLS.md`](engines/baiyan/TOOLS.md)。

## 常用命令

### 后端与数据库

| 用途 | 命令 |
| --- | --- |
| 构建 API / Worker | `make build` |
| 全量后端测试（race + coverage） | `make test` |
| Go lint | `make lint` |
| Go 静态检查 | `go vet ./...` |
| 生成 sqlc 代码 | `make sqlc` |
| 数据库升级 | `make migrate-up` |
| 回滚一个迁移 | `make migrate-down` |
| 查看迁移版本 | `make migrate-status` |

### 前端

| 用途 | 命令 |
| --- | --- |
| 开发服务器 | `pnpm --dir web dev` |
| 测试 | `pnpm --dir web test` |
| Lint | `pnpm --dir web lint` |
| 类型检查 | `pnpm --dir web typecheck` |
| 生产构建 | `pnpm --dir web build` |

### 引擎与集成

| 用途 | 命令 |
| --- | --- |
| Baiyan 被动运行时测试 | `cd engines/baiyan && go test ./internal/contract ./internal/job ./internal/capability ./internal/engine ./internal/toolrunner ./cmd/baiyan-engine -race` |
| Baiyan Engine 构建 | `cd engines/baiyan && go build ./cmd/baiyan-engine` |
| 被动链路 E2E | `make e2e-passive` |
| Engine 镜像安全验证 | `make test-baiyan-image` |

`engines/baiyan` 是独立 Go module，根目录的 `make test` 不会覆盖它，提交前应分别执行两组测试。

## API 契约

- ASM Platform API：[`api/openapi.yaml`](api/openapi.yaml)
- Engine Contract v1：[`api/engine-openapi.yaml`](api/engine-openapi.yaml)

除登录、Token 刷新和带独立认证的 Engine callback 外，业务 API 默认要求 JWT；项目级资源同时执行后端权限与项目隔离校验。

## 安全约束

- 默认禁止扫描未授权范围，Scope exclude 和危险地址拒绝优先。
- 主动发现默认关闭，不应通过前端隐藏按钮代替后端授权。
- callback 使用 Engine identity、HMAC、时间窗口、序号和持久 inbox 防止伪造、冲突与永久丢失。
- Webhook、Provider 等出站请求设置 SSRF 防护、超时、响应上限，并禁止不受控重定向。
- 不记录或返回 Token、Cookie、Secret、AK/SK、完整 Provider 响应或 PoC 数据。
- Baiyan 容器以非 root、只读根文件系统、`cap_drop: ALL` 和 `no-new-privileges` 运行。
- `docker-compose.yml` 包含本地开发 fallback；生产环境必须使用独立 Secret 管理、TLS、数据库备份和受限网络。

## License

内部项目，未公开授权。
