# ASM 暴露面风险管理平台

> 以资产为中心、以变化为驱动、以风险闭环为目标的攻击面管理（Attack Surface Management）平台。

持续管理企业互联网暴露面，覆盖资产发现、暴露面识别、风险评估、处置闭环与管理报表。
探测、存活、扫描、资产发现由外部引擎执行；平台负责**编排调度、风险建模与闭环管理**。

## 核心能力

- 项目与授权范围（Scope）管理
- 资产管理（域名 / IP / 端口 / 网站 / 证书）与资产关系图谱
- 调度外部引擎执行发现 / 存活 / 扫描，结果归一化入库
- 暴露面分类与高危暴露识别
- 风险识别、可配置评分、状态流转闭环
- 变化监控（新增 / 消失 / 关键变更事件）
- 工单闭环（分派、整改、复测、SLA）
- 报表与修复效能看板

## 技术栈

- **后端**：Go + Gin + sqlc + MySQL 8.0 + Redis(asynq) + casbin
- **前端**：React + TypeScript + Vite + Ant Design Pro
- **部署**：Docker Compose（api / worker / mysql / redis）

## 架构

- `api`：HTTP 服务 + 认证鉴权（RBAC）+ 业务逻辑 + 引擎回调入口
- `worker`：异步任务（下发引擎、结果入库、变更检测、风险评分、通知、超时回收）
- 外部探测引擎：通过 **HTTP 下发 + Webhook 回调** 对接，平台内不实现主动探测

## 目录结构

```
cmd/api, cmd/worker   # 两个进程入口
internal/             # 业务模块：auth project asset discovery exposure risk ticket report notification
migrations/           # 数据库迁移（golang-migrate）
api/                  # OpenAPI 契约
web/                  # 前端（React + Ant Design Pro）
```

## 本地开发

> 项目骨架建设中，以下为目标使用方式。

### 依赖

- Go 1.22+
- Node 20+ 与 pnpm
- Docker / Docker Compose

### 启动

```bash
cp .env.example .env          # 按需修改
docker compose up -d mysql redis
make migrate-up               # 执行数据库迁移
make build                    # 编译 api / worker
docker compose up -d          # 启动全部服务

# 前端
cd web && pnpm install && pnpm dev
```

### 常用命令

| 端 | 命令 |
| --- | --- |
| 后端构建 | `make build` |
| 后端测试 | `make test` |
| 后端 Lint | `make lint` |
| 数据库迁移 | `make migrate-up` / `make migrate-down` |
| 前端开发 | `pnpm dev` |
| 前端构建 | `pnpm build` |
| 前端测试 | `pnpm test` |

## 配置

所有配置通过环境变量提供，参见 `.env.example`；敏感配置不入库。

## 状态

MVP 开发中。

## License

内部项目，未公开授权。
