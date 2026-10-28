# Apocalypse

Apocalypse 是一个原创的、面向授权 Web 安全评估的扫描平台，提供完整 DAST 工作流：目标扫描、同站爬取、漏洞规则、任务存储、Web 控制台和报告导出。重点是可审计、可扩展和默认非破坏性的扫描闭环。

## 已实现（v0.10）

- Web 控制台：仪表盘、扫描、漏洞、浏览器点选录制、批量任务、团队/SSO/工单
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
PYTHONPATH=src python3 -m unittest discover -s tests -v
```
