# Apocalypse

Apocalypse 是一个原创的、面向授权 Web 安全评估的扫描平台，提供完整 DAST 工作流：目标扫描、同站爬取、漏洞规则、任务存储、Web 控制台和报告导出。重点是可审计、可扩展和默认非破坏性的扫描闭环。

## 已实现（v0.10）

- Web 控制台：仪表盘、扫描、漏洞、浏览器点选录制、批量任务、质量评测、团队/SSO/工单
- 精确范围控制、SSRF 防护、请求预算、**扫描策略排除**（规则/路径/参数）
- HTTP + Playwright 浏览器爬虫、OpenAPI、GraphQL introspection
- **API 原生探测**：OpenAPI query/JSON body/header、GraphQL 参数
- XSS 上下文分类 + **Chromium 弹窗执行验证**（`--browser-verify`）
- **双会话 IDOR/BOLA**（`--secondary-header`）
- LFI / SSTI / SSRF（OAST）确认链；Deep 盲注 TFT + 时间链
- 报告：**HTML / JSON / SARIF**，附带 **CWE / OWASP** 映射
- 登录录制、基线、定时、Webhook、CI `--fail-on`、SSO/多租户、Jira/ServiceNow

## 安装

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
pip install -e '.[browser]'   # 浏览器功能；优先使用本机 Google Chrome，一般无需再下载 Chromium
# 若本机没有 Chrome / Edge，再执行：python -m playwright install chromium
```

完整的本地安装、团队部署、升级回滚和安全加固说明见 [`docs/INSTALL.md`](docs/INSTALL.md)。

## 控制台

```bash
apocalypse serve
```

打开 http://127.0.0.1:8080

## CLI 示例

```bash
# 策略模板
apocalypse policy-template --output policy.json

# 深度扫描：API + 浏览器 XSS 验证 + IDOR + OAST + 策略
apocalypse scan --target https://app.example.com/ --profile deep \
  --openapi-url https://app.example.com/openapi.json --graphql \
  --header 'Cookie: session=user-a' \
  --secondary-header 'Cookie: session=user-b' \
  --browser-verify --browser-crawl --blind-inject --submit-forms \
  --oast-listen 127.0.0.1:0 --policy policy.json \
  --fail-on high --ack-authorized

# SARIF（CI / code scanning）
apocalypse report SCAN_ID --format sarif --output findings.sarif
```

## 安全边界

仅扫描你拥有或已获明确授权的系统。自动化发现必须人工验证后才能提交。

## 开发

```bash
pip install -e '.[dev]'
coverage run -m unittest discover -s tests -p 'test_core.py' -v
coverage report
python benchmark/run_lab.py
APOCALYPSE_E2E=1 python -m unittest discover -s tests -p 'test_e2e.py' -v
```

CI 对单元测试、全包分支覆盖率基线（实测 47%，门槛 45%）、Chromium 控制台 E2E，以及多漏洞家族回环靶场的 precision/recall 门槛进行独立验收。真值清单位于 `benchmark/ground_truth.json`，审核流程见 `benchmark/REVIEW.md`，结果写入 `benchmark/results/latest.json`。该靶场用于防回归，不代表对真实世界漏洞检出率的完整声明。

当前靶场真值版本 `2026-10-28.1` 包含 19 个位置（15 个正样本、4 个负样本），覆盖 XSS、SQLi、命令注入、LFI、SSTI、SSRF、开放重定向、IDOR、CORS、敏感信息、错误泄露、Cookie 与明文密码表单等 13 个家族。当前受控基线为 Precision / Recall / F1 均为 1.0；人工签字状态以真值清单中的 `human_signoff` 为准。

控制台的“质量评测”页会展示上述指标、逐家族 TP/FP/FN、覆盖率、测试数和签字状态。在源码仓库模式下，管理员可以直接点击“运行本地靶场”，评测在后台完成后页面会自动刷新。
