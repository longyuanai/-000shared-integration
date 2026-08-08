# 000shared-integration · Phase-2

> 状态基线：2026-08-09。M2.1 预生产验收与 M2 运维发布门禁均已完成。

## 已完成

- 6 产品 JSON subprocess adapter 与统一 CLI Envelope。
- API key 认证、幂等、Finding 持久化和重试/超时边界。
- SQLite / PostgreSQL 存储路径与迁移基础。
- 队列、worker lease/reclaim 和多实例准备。
- 容器构建、私有 GHCR 发布、Render + Neon 预生产部署。
- 真实 Gateway 的 Chromium 与 Mobile 浏览器 E2E。
- PostgreSQL 备份/恢复实演、3 轮并发验证、seed schema 修复与 100 项全量测试。

当前代码与数据库架构详见 `docs/architecture.md`，部署和恢复步骤见 `DEPLOYMENT.md`。

## M2 运维门禁结果

`../000shared-llm-core/docs/dispatches/008-M2-OPS.md` 已本地执行：

1. 独立源库与恢复库的 revision、tenant、Finding、Job 和审计行数一致。
2. 真实 PostgreSQL 集成测试连续 3 次通过。
3. E2E Python/SQL seed 在空迁移库和重复运行场景通过。
4. Ruff、全量 100 passed、admin CLI 和 Gateway `/livez` 通过。

审计见 `AUDIT/008-M2-OPS.md`。Integration `4001790`、web-ui `e5a5274` 与 core
`ffd75e6` 已推送。run `31188096745` 暴露 workflow 旧默认 SHA 后，core `e900a0a` 改为
从 suite lock 解析 refs；替代 run `31267714152` 完成 9 仓锁校验与 `1873 passed,
5 skipped, 1 warning, 0 failed`。审计已升级为 PASS。

## M3 候选范围

身份边界已在 core [`ADR-003`](../000shared-llm-core/docs/adr/ADR-003-M3-BFF-identity-boundary.md)
固化，并由 [`009-M3-AUTH`](../000shared-llm-core/docs/dispatches/009-M3-AUTH.md) 派活。
两者已接受/解锁；按 009 顺序实施：

- `AUTH-DATA-001` 已完成并通过候选 suite CI；`AUTH-HTTP-001` 已完成并推送，
  Integration `c775e12` 的候选 suite CI run `31271147360` 成功（`1908 passed,
  7 skipped, 1 warning`）。
- 下一项为 Web OIDC/BFF 适配器与安全 cookie（`UI-SESSION-001`）。
- tenant-aware API、RBAC 和审计边界。
- 生产级迁移策略、容量基线、指标和告警。
- 备份策略、恢复目标与周期性恢复演练。
- 持续流量和故障注入验收。

## 非目标

- 不在 M2 运维派活中重构产品业务逻辑。
- 不对生产数据库执行恢复、删库或压力测试。
- 不把连接串、Token 或密钥写入仓库和审计证据。
