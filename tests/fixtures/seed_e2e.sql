-- seed_e2e.sql — deterministic Finding + Job fixtures for web-ui live-mode e2e.
-- Run with:
--   docker exec -i 000shared-integration-postgres-1 psql -U integration -d integration < seed_e2e.sql
-- Idempotent: wipes prior e2e-tagged rows before reinserting.

BEGIN;

DELETE FROM correlation_findings WHERE correlation_id IN (
    SELECT id FROM correlations WHERE tenant_id = 'e2e'
);
DELETE FROM correlations WHERE tenant_id = 'e2e';
DELETE FROM findings WHERE tenant_id = 'e2e';
DELETE FROM job_events WHERE tenant_id = 'e2e';
DELETE FROM jobs WHERE tenant_id = 'e2e';

INSERT INTO findings (
    tenant_id, finding_id, fingerprint, source, severity, confidence, status,
    asset, cve, title, description, first_seen, last_seen,
    occurrences, job_id, assigned_to, payload, created_at, updated_at
) VALUES
('e2e', 'e2e-f0001', 'e2e:c006critical', '006', 'critical', 0.98, 'open',
    'edge-gateway-07', 'CVE-2024-3094',
    'OpenSSL 组件命中已知在野利用漏洞', '',
    now() - interval '9 minutes', now() - interval '4 minutes',
    3, NULL, NULL,
    '{"id":"e2e-f0001","source":"006","severity":"critical","confidence":0.98,"title":"OpenSSL 组件命中已知在野利用漏洞","asset":"edge-gateway-07","cve":"CVE-2024-3094"}',
    now(), now()),
('e2e', 'e2e-f0002', 'e2e:c001high', '001', 'high', 0.94, 'confirmed',
    'auth-prod-02', NULL,
    '同一来源 IP 触发凭据填充关联规则', '',
    now() - interval '17 minutes', now() - interval '12 minutes',
    8, NULL, 'SOC Team',
    '{"id":"e2e-f0002","source":"001","severity":"high","confidence":0.94,"title":"同一来源 IP 触发凭据填充关联规则","asset":"auth-prod-02","assigned_to":"SOC Team"}',
    now(), now()),
('e2e', 'e2e-f0003', 'e2e:c004high', '004', 'high', 0.91, 'open',
    'payments-api', NULL,
    '未净化用户输入进入系统命令执行', '',
    now() - interval '27 minutes', now() - interval '22 minutes',
    1, NULL, NULL,
    '{"id":"e2e-f0003","source":"004","severity":"high","confidence":0.91,"title":"未净化用户输入进入系统命令执行","asset":"payments-api"}',
    now(), now()),
('e2e', 'e2e-f0004', 'e2e:c003medium', '003', 'medium', 0.88, 'open',
    'research-agent', NULL,
    '间接提示注入绕过工具调用边界', '',
    now() - interval '36 minutes', now() - interval '31 minutes',
    2, NULL, NULL,
    '{"id":"e2e-f0004","source":"003","severity":"medium","confidence":0.88,"title":"间接提示注入绕过工具调用边界","asset":"research-agent"}',
    now(), now()),
('e2e', 'e2e-f0005', 'e2e:c002medium', '002', 'medium', 0.86, 'accepted_risk',
    'vpn.example.internal', 'CVE-2023-23397',
    '外网资产存在高 EPSS 漏洞组合', '',
    now() - interval '52 minutes', now() - interval '47 minutes',
    2, NULL, NULL,
    '{"id":"e2e-f0005","source":"002","severity":"medium","confidence":0.86,"title":"外网资产存在高 EPSS 漏洞组合","asset":"vpn.example.internal","cve":"CVE-2023-23397"}',
    now(), now()),
('e2e', 'e2e-f0006', 'e2e:c005low', '005', 'low', 0.79, 'resolved',
    'sample-98af.exe', NULL,
    '可疑样本包含动态解析 API 行为', '',
    now() - interval '76 minutes', now() - interval '71 minutes',
    1, NULL, NULL,
    '{"id":"e2e-f0006","source":"005","severity":"low","confidence":0.79,"title":"可疑样本包含动态解析 API 行为","asset":"sample-98af.exe"}',
    now(), now()),
('e2e', 'e2e-f0007', 'e2e:c001info', '001', 'info', 0.65, 'open',
    'scheduler', NULL,
    '扫描器版本升级提示', '',
    now() - interval '100 minutes', now() - interval '95 minutes',
    1, NULL, NULL,
    '{"id":"e2e-f0007","source":"001","severity":"info","confidence":0.65,"title":"扫描器版本升级提示","asset":"scheduler"}',
    now(), now());

INSERT INTO jobs (
    id, tenant_id, source, status, queue, input, progress,
    attempt, cancel_requested, result_count,
    error_code, error_message, created_at, updated_at
) VALUES
('e2e-job-001', 'e2e', '004', 'running', 'analysis',
    '{"seeded_by":"seed_e2e"}', 0.5,
    1, false, 2, NULL, NULL,
    now() - interval '35 minutes', now() - interval '30 minutes'),
('e2e-job-002', 'e2e', '001', 'succeeded', 'fast',
    '{"seeded_by":"seed_e2e"}', 1.0,
    1, false, 1, NULL, NULL,
    now() - interval '50 minutes', now() - interval '45 minutes'),
('e2e-job-003', 'e2e', '006', 'failed', 'sandbox',
    '{"seeded_by":"seed_e2e"}', 0.3,
    2, false, 0, 'ADAPTER_TIMEOUT', '分析超过时间限制',
    now() - interval '65 minutes', now() - interval '60 minutes');

COMMIT;