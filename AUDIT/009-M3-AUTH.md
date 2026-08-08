# 009-M3-AUTH 审计报告

> 执行日期：2026-08-09  
> 结论：**PASS-WITH-NITS**（代码与真实门禁通过；Sites 发布访问待恢复）

## 范围

- `AUTH-DATA-001`：identity client、短时 user session、Alembic 与 admin CLI。
- `AUTH-HTTP-001`：身份交换、会话撤销、机器/用户双认证、逐请求 Membership RBAC。
- `UI-SESSION-001`：Hosting/OIDC + PKCE、HttpOnly cookie、same-origin BFF、退出/换租户。
- `E2E-RBAC-001`：真实 PostgreSQL + Gateway + Web 的多租户浏览器门禁。
- `DOC-AUTH-001`：环境变量、迁移、轮换、回滚和故障排查 Runbook。
- 未触碰 `003AI Agent安全靶场` 的用户修改，未使用生产凭据或客户身份数据。

## 实施证据

| 仓库 | 候选提交 | 内容 |
|---|---|---|
| Integration | `8598aaf` | 身份持久化、迁移、repository、admin CLI |
| Integration | `d87d194` | HTTP 身份交换、双认证、测试与候选记录 |
| Integration | `15a905b` | 隔离 RBAC fixture、真实栈 Compose 与夹具测试 |
| Web | `5943c67` | Hosting/OIDC、BFF 会话、安全 cookie 与代理迁移 |
| Web | `3dbc361` | 13 场景真实 RBAC、双轮编排、admin 门禁代理 |
| Core | `d41bfea` | suite CI 增加真实双轮 PostgreSQL/Gateway/Web 门禁 |

数据库 revision 为 `20260809_0002`。identity client 使用 scrypt 保存长期 secret；高熵
`igs_...` 会话只保存 SHA-256 摘要，默认 5 分钟、上限 15 分钟。

## 本地验证

| 门禁 | 结果 |
|---|---|
| Integration 全量（SQLite 默认） | `139 passed, 4 skipped` |
| 真实 PostgreSQL 16 专项 | `4 passed`；Alembic 升级到 `20260809_0002` |
| Ruff | `src tests` 全绿 |
| Web lint / 两套 typecheck / Vinext build | 全绿 |
| Web Node tests | 28 auth/session + 6 built route + 3 render = `37 passed` |
| 真实浏览器 RBAC | 两个独立 round，各 `13 passed` |
| 夹具清理 | 每轮精确标签清理；最终容器、网络和临时数据库为 0 |

一次尝试把 `INTEGRATION_DATABASE_URL` 注入整个测试集时，使专门验证 SQLite Alembic 的
测试被环境覆盖；PostgreSQL 的 4 个专项当时均已通过。随后按既有分层重新执行，得到上表
两个干净结果，未通过跳过或改测试规避。

## 远端门禁

- Web CI [`31276154427`](https://github.com/longyuanai/web-ui/actions/runs/31276154427)：
  lint、typecheck、build、37 个 Node tests 和 Chromium/Mobile 12 个 Demo E2E 均成功。
- 候选 suite CI
  [`31276172231`](https://github.com/longyuanai/000shared-llm-core/actions/runs/31276172231)：
  精确检出 Integration `15a905b` 与 Web `3dbc361`；八个 Python 组共
  `1914 passed, 7 skipped, 1 warning`；真实 RBAC 两轮各 `13 passed`，每轮后清理成功。

## 安全检查

- viewer 读成功、viewer 写 403、analyst 写成功、admin-only route 仅 admin 200。
- 无 Membership 与跨租户交换均 403；Tenant B Job 对 Tenant A 会话为 404。
- Membership 停用、过期和退出后的下一请求均 401。
- 浏览器只访问 Web origin；bridge secret、机器 key 和会话值不出现在 DOM、Web Storage、
  URL、请求正文、响应正文或非 cookie 头。Cookie/Set-Cookie 仅承担预期 HttpOnly 传输。
- inbound Authorization、用户、角色和租户头由 BFF 丢弃；写操作要求同源 Fetch Metadata
  与 JSON content type。
- `openid-client 6.8.4` 固定版本，Next `16.3.0`；生产依赖 audit 为 0。
- secret pattern scan 与三仓 `git diff --check` 通过。

## 发布、回滚与剩余项

- 发布和双密钥轮换步骤见 [`docs/m3-auth-rollout-rollback.md`](../docs/m3-auth-rollout-rollback.md)。
- 首选保留 additive schema，按 Gateway 后、Web 前的逆序回滚应用；数据库 downgrade 是最后
  手段，会删除 M3 身份数据。
- 现有 Sites `project_id` 在当前连接账号下返回“project not found”。因此没有创建替代站点、
  没有覆盖现网，也没有注入生产 secret。恢复原项目访问、配置运行时值并完成私有发布后，
  本报告可从 PASS-WITH-NITS 升级为 PASS。
- Render 私有 GHCR 拉取凭据须在 2026-08-14 前轮换或随服务下线撤销。
