# 000shared-integration · Phase-2 计划

> **本仓角色**: 6 产品 ↔ IntegrationGateway 的横向适配层。`JSONSubprocessAdapter` 在端口 8080 把 6 个产品的 CLI 包成统一 HTTP API。
> **当前状态**: v0.6 §15 CLI Envelope 契约已实施,6 产品适配中,**6/6 worker 4 件套全绿**。
> **下一阶段**: v0.6 收尾 + v0.7+ 增厚。

---

## 现状摘要(2026-07-25)

| 项 | 状态 |
|----|------|
| `JSONSubprocessAdapter` 基础 | ✅ |
| 6 产品 CLI 子进程调用 | ✅(payload 表见 v0.5 §15.4) |
| Envelope 归一化(source 注入 / 缺字段默认值 / JSON 校验)| ✅ |
| `ProductCLIError` 错误透传 stderr | ✅ |
| `/v0.5/health` 聚合 6 产品 | ✅ |
| e2e 测试 `tests/integration/test_cli_envelope_smoke.py` | ⚠️ Hook 005-FINAL-001 待做(覆盖 6 产品真子进程)|
| timeout / circuit breaker | ⚠️ timeout 待做，RBAC/持久化已落地 |
| 健康检查深度化(active probing)| ❌ Phase-2 Hook B |
| 多租户 Bearer RBAC | ✅ viewer / analyst / admin |
| Finding / correlation 持久化 | ✅ tenant-isolated SQLite |
| 生产容器 | ✅ suite-root OCI Dockerfile |

---

## Phase-2 hooks

### Hook A · retry + timeout(v0.6 末)

**目标**:为 `JSONSubprocessAdapter` 加超时和限流重试。

**派活文档**:`011-ADAPTER-RETRY.md`(待起草)

```python
class JSONSubprocessAdapter:
    def __init__(
        self,
        cli_path: Path,
        *,
        timeout: float = 30.0,         # v0.7 加
        max_retries: int = 2,          # v0.7 加
        retry_backoff: float = 1.0,    # 指数退避
    ): ...

    async def scan(self, payload):
        for attempt in range(self.max_retries + 1):
            try:
                proc = await asyncio.wait_for(
                    asyncio.create_subprocess_exec(...),
                    timeout=self.timeout,
                )
                ...
            except asyncio.TimeoutError:
                if attempt < self.max_retries:
                    await asyncio.sleep(self.retry_backoff * 2 ** attempt)
                    continue
                raise ProductCLIError(...)
```

**测试**:
- product CLI 故意 sleep 60s → adapter 在 timeout 后 raise
- product CLI 故意 RC=1 → adapter 第 1 次重试 → 第 2 次成功
- product CLI 不存在 → adapter 立即 raise(不重试)

**为什么 Phase-2**:
- v0.5 单产品 CLI 跑都很快,timeout 不急
- v0.6 真接大流量(单次 scan 可能 N 分钟),必须有超时
- 不阻塞后续 v1.0 多租户

### Hook B · 健康检查 active probing(v0.7+)

**目标**:`/v0.5/health` 现在调 `adapter.health()`(子进程),改成 active probing(grep 一下 product CLI `--help` 看是否响应)。

**派活文档**:`012-ADAPTER-HEALTH.md`(待起草)

```python
async def health(self) -> dict:
    proc = await asyncio.create_subprocess_exec(
        python_exe, "-m", self.module, "--help",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, _ = await proc.communicate()
    if proc.returncode == 0 and b"usage:" in stdout.lower():
        return {"status": "ok"}
    return {"status": "degraded", "reason": "CLI not responsive"}
```

**测试**:
- 6 产品 active probing 都 OK → all products ok
- 模拟某产品 CLI RC=2 → degraded status

**为什么 Phase-2**:
- 现状 health() 不可信(各产品实现不一定真 health)
- v0.6 接 N 产品后健康判断要可靠

---

## v1.0 路线图

```
v0.6 (现在):
  - Hook A: retry + timeout
  - 005-FINAL-001: e2e CLI envelope smoke(6 产品)

v0.7:
  - Hook B: active health probing
  - SQLAlchemy / DB-backed FindingRegistry 走 000shared-llm-core 但 adapter 要适配
  
v1.0:
  - 6 产品全 v1.0
  - 集成层负载均衡(若产品有 multi-instance,可轮询)
  - 多租户 token 鉴权(与 000shared-llm-core §17 同步)
```

---

## 不要做的事

- ❌ 不要替产品仓写业务逻辑(找产品 Codex 写)
- ❌ 不要在 adapter 里加新字段兼容性归一化(那是 v0.5 §15 已冻结)
- ❌ 不要把 `JSONSubprocessAdapter` 拆成多版本(向后兼容是产品 CLI 的事)

---

**最近修订**: 2026-07-25 · Claude 起草 Phase-2 计划
**下次回看触发**: v0.6 完成 / Hook A 启动 / v0.7+
