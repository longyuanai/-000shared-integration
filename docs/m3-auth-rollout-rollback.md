# M3 身份、会话与 RBAC 发布 / 轮换 / 回滚 Runbook

> 适用范围：Alembic revision `20260809_0002`、IntegrationGateway 数据库鉴权、
> Web Hosting/OIDC 身份适配器和 `igs_...` 用户会话。所有命令中的大写值都是占位符。

## 1. 不变量

- PostgreSQL/Gateway 是 Tenant、Membership、角色和会话的唯一授权事实源。
- `igb_...` identity bridge 只用于 `/v1/auth/exchange`，不替代 `igw_...` 机器 API Key。
- 浏览器只持有 HttpOnly cookie，不接收 bridge secret、机器 key 或会话响应正文。
- 生产 Web 只使用 `__Host-longyuan_session; Path=/; HttpOnly; Secure; SameSite=Lax`。
- 生产故障保持 fail-closed，不切回 Demo 数据。
- 日志、工单、截图、CI artifact、Shell history 和 Git 中均不记录凭据明文。

## 2. 发布前检查

1. 对目标 PostgreSQL 做可恢复备份，并记录备份时间、revision 和恢复位置，不记录连接串。
2. 确认当前 schema revision、Gateway/Web 镜像 digest 和回滚提交。
3. 确认至少一个 active Tenant，以及目标用户对应的 active Membership。
4. 确认 Web 的公开 URL、Hosting issuer 或 OIDC issuer/client/redirect URI 完全一致。
5. 先在预生产运行 `npm run test:e2e:rbac`；每轮应为 `13 passed` 且测试栈无残留。
6. 在变更窗口内保留上一版 Gateway/Web 镜像和上一枚 bridge client，直到新链路验收完成。

建议回滚点：

| 组件 | 已验证回滚提交 | 说明 |
|---|---|---|
| Gateway | `d87d194bfa86b4397df1659d8d134db293c54b9c` | M3 双认证和 HTTP 身份交换候选 |
| Web | `5943c67ba0270cd779f7e056535fa7af40ceef4e` | M3 Hosting/OIDC + HttpOnly 会话候选 |
| M2 完整锁 | Core `6271e62` / Integration `fc272aa` / Web `31ddd60` | 仅作为整套灾难回退基线 |

首选回滚到上表的 M3 候选，继续使用用户会话边界。整套回到 M2 会重新引入旧机器令牌
用户路径，只能作为隔离故障后的短时灾难恢复，并需单独审批和审计。

## 3. 环境变量

### Gateway

| 变量 | 生产要求 |
|---|---|
| `INTEGRATION_DATABASE_URL` | PostgreSQL 连接串，由 Secret Manager 注入 |
| `INTEGRATION_AUTH_REQUIRED` | `true` |
| `INTEGRATION_AUTH_BACKEND` | `database`；短时兼容窗口才使用 `hybrid` |
| `INTEGRATION_AUTH_TOKENS` | database 模式为空；机器客户端使用数据库 `igw_...` key |
| `INTEGRATION_AUTH_EXCHANGE_RATE_LIMIT` | 每个窗口允许次数，默认 `20` |
| `INTEGRATION_AUTH_EXCHANGE_RATE_WINDOW_SECONDS` | 限流窗口秒数，默认 `60` |
| `INTEGRATION_AUTO_CREATE_SCHEMA` | 生产必须关闭；schema 只由 Alembic 迁移 |

### Web

| 变量 | 生产要求 |
|---|---|
| `APP_MODE` | `live` |
| `GATEWAY_URL` | Gateway 内部 HTTPS/受控网络地址 |
| `GATEWAY_IDENTITY_CLIENT_TOKEN` | 新建或轮换得到的一次性 `igb_...` secret |
| `GATEWAY_TENANT_ID` | 默认租户请求；最终授权仍取决于 Membership |
| `WEB_IDENTITY_PROVIDER` | Sites 为 `hosting`；独立部署为 `oidc` |
| `WEB_IDENTITY_ISSUER` | Hosting issuer，必须在 identity client allowlist 中 |
| `OIDC_ISSUER` / `OIDC_CLIENT_ID` / `OIDC_REDIRECT_URI` | OIDC 公开配置；Hosting 留空 |
| `OIDC_CLIENT_SECRET` | OIDC confidential client 才注入；不加 `NEXT_PUBLIC_` |
| `SITE_URL` | 与浏览器 Origin、OIDC 回调和公开站点一致 |
| `DASHBOARD_AUTH_REQUIRED` | `true` |

生产 Web 不配置 `GATEWAY_TOKEN`。环境模板见 `web-ui/.env.example`。

## 4. 首次发布顺序

### 4.1 迁移数据库

使用与待发布 Gateway 相同版本的镜像执行：

```text
alembic -c alembic.ini current
alembic -c alembic.ini upgrade head
alembic -c alembic.ini current
```

结果必须为 `20260809_0002`。迁移是加表、加索引和 Membership 状态字段；旧 Gateway 不会
使用新增对象，因此迁移后可先观察，再切换应用。

### 4.2 创建 identity client

在受控 admin shell 中运行，issuer 可以重复传入：

```text
shared-integration-admin identity-client-create \
  --name "Dashboard BFF" \
  --issuer HOSTING_OR_OIDC_ISSUER
```

命令只在此时输出一次 token。把 token 直接写入部署平台 Secret Manager；不得复制到聊天、
工单或普通文件。随后运行 `shared-integration-admin identity-client-list`，只核对 client ID、
prefix、allowlist 和 active 元数据。

### 4.3 准备用户和 Membership

身份交换会幂等创建/更新 User，但不会自动创建 Membership。已知身份可提前执行：

```text
shared-integration-admin user-upsert \
  --issuer HOSTING_OR_OIDC_ISSUER \
  --subject PROVIDER_SUBJECT \
  --email USER_EMAIL \
  --display-name DISPLAY_NAME

shared-integration-admin membership-set \
  --tenant TENANT_ID \
  --user USER_ID \
  --role viewer|analyst|admin \
  --actor CHANGE_TICKET
```

### 4.4 先 Gateway，后 Web

1. 部署 Gateway，保持既有 `igw_...` 机器客户端兼容。
2. 验证 `/livez`、带授权的 `/readyz`、旧机器 key 和 audit 写入。
3. 把 identity client token、默认 tenant、issuer/OIDC 配置注入 Web。
4. 部署 Web；确认生产响应只设置 `__Host-longyuan_session`。
5. 以 viewer 读、viewer 写 403、analyst 写、admin 管理读、无成员 403、跨租户 403 验收。
6. 验证退出后为 401、Membership 停用后下一请求为 401，且 DOM/Storage/URL/日志无 token。

## 5. Bridge 双密钥轮换

1. `identity-client-list` 记录当前 client ID 和 prefix（不记录 secret）。
2. 创建轮换 client：

   ```text
   shared-integration-admin identity-client-rotate --identity-client OLD_CLIENT_ID
   ```

3. 将一次性新 token 更新到 Web Secret Manager，滚动部署 Web。
4. 用新部署完成身份交换、viewer 读和 analyst 写；观察 401/429 与失败审计。
5. 确认旧实例已退出后撤销旧 client：

   ```text
   shared-integration-admin identity-client-revoke --identity-client OLD_CLIENT_ID
   ```

6. 再次执行 `identity-client-list`，确认旧 client inactive、新 client active。

撤销 identity client 会让它签发的现有用户会话在下一请求失效。若新 token 验证失败，先把
Web Secret 切回仍 active 的旧 token，不改数据库；定位完成后撤销失败的新 client。

## 6. 会话处置与清理

单会话撤销：

```text
shared-integration-admin user-session-revoke \
  --tenant TENANT_ID \
  --session SESSION_ID \
  --actor CHANGE_TICKET
```

清理已过期会话：

```text
shared-integration-admin user-session-cleanup
```

清理不删除审计事件。禁用 Tenant、Membership 或 identity client 会在下一请求即时生效，
适合紧急撤权；恢复前必须确认撤权原因和审计记录。

## 7. 回滚

### Web 失败

1. 保持 Gateway 和 `20260809_0002` schema 不变。
2. 回滚到已验证 Web M3 候选，恢复上一枚仍 active 的 bridge secret。
3. 验证 cookie、交换、读取和退出；新 client 若不再使用则撤销。

### Gateway 失败

1. 停止 Web 新流量或进入维护页，避免循环交换。
2. 回滚到已验证 Gateway M3 候选；保留新增表和 identity clients。
3. 验证旧机器 key、M3 用户会话和审计，再恢复 Web。

### 数据库迁移

首选保留 additive schema 并回滚应用。`alembic downgrade 20260805_0001` 会删除 identity
clients、user sessions 和 Membership status，只能在已备份、Web/Gateway 均回滚、确认这些
数据可丢弃并得到变更批准后执行。执行后必须做恢复演练和审计核对。

## 8. 故障排查

| 现象 | 检查 | 处置 |
|---|---|---|
| exchange 401 | bridge prefix、active/revoked、issuer allowlist | 修正 issuer 或切回 active client；不输出 secret |
| exchange 403 | Tenant 与 Membership 是否存在且 active | 由管理员建立/恢复 Membership；不从错误正文枚举账号 |
| session 401 | TTL、session/client/Tenant/Membership 状态 | 重新验证上游身份并交换；必要时恢复成员状态 |
| 写操作 403 | 当前角色、Origin/Host、`Sec-Fetch-Site`、JSON | 校正角色或同源请求；不绕过 BFF 门禁 |
| Web 502 | `GATEWAY_URL`、Gateway health、网络/DNS | 回滚 Web 或恢复 Gateway；保持 fail-closed |
| 生产 cookie 缺失 | HTTPS、`SITE_URL`、cookie 名称和 Secure | 只修部署配置，不改用开发 cookie |
| OIDC 回调失败 | issuer/client/redirect、state/nonce/PKCE | 核对提供方配置；不记录 code/token |
| Sites “project not found” | 当前连接账号和既有 `project_id` | 恢复原项目访问；不得创建替代项目覆盖事实源 |

## 9. 发布完成证据

- 精确 Gateway/Web/Core commit 与镜像 digest。
- Alembic revision、备份/恢复点和无秘密值的变更单号。
- identity client ID/prefix、issuer allowlist、轮换/撤销时间（不含 secret/hash）。
- viewer/analyst/admin、无成员、跨租户、过期、退出和即时撤权结果。
- Web CI、suite CI 链接，依赖审计、secret scan 和测试计数。
- 回滚演练结果、剩余风险、Sites/Render 凭据到期处置状态。
