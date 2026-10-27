# Sentinel SRC

一个面向**已获授权 SRC / 漏洞赏金项目**的低风险 Web 检测与报告工具。它默认保守：目标必须命中显式白名单，禁止访问私网地址，重定向后的每一跳都会重新校验范围，并且只执行 GET/HEAD 类检查。

## 能做什么

- HTTP 安全头、Cookie 属性与 CORS 基线检查
- 严格同主机的轻量 HTML/JavaScript 端点发现（无查询参数、无攻击 payload）
- 私钥/云密钥形态、调试堆栈和内网地址的被动线索检测，证据只保存脱敏指纹
- 少量低风险公开文件检查（如 `/.well-known/security.txt`、`/robots.txt`）
- 并发与每主机速率限制
- 响应证据截断与常见秘密脱敏
- 输出 JSON 证据包和适合人工编辑的 Markdown 漏洞报告
- 将结果拆分为 `candidate_count`、`suspicious_count` 与 `noise_count`；加固项默认进噪声
- 批量/定时扫描后单独写出 `suspicious.json`、`suspicious.md`、`candidates.json`
- `watch` 按间隔复扫授权目标清单，有可疑项时在终端提示
- `authz-compare`：双账号 GET 权限差分（仅 `automation_allowed = true` 的项目）
- `inbox-from-manual`：把人工验证 Markdown 整理进可疑收件箱（不发网络请求）
- `submit` 命令只生成待提交包；不会自动向第三方平台发送

它不是漏洞“全自动确认器”。扫描结果可能有误报，提交前必须人工复现、判断影响，并遵守目标项目的测试规则。

## 快速开始

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
cp config.example.toml config.toml
# 编辑 allow_hosts，只填写你已获得测试授权的域名
sentinel-src scan --config config.toml --target https://example.com
sentinel-src report --input runs/latest.json --output runs/report.md
sentinel-src submit --input runs/latest.json --output runs/submission.json
```

批量初筛只读取人工准备的完整 URL 清单，不进行子域发现。每批最多 50 个目标，并且需要显式确认已核对实时授权范围：

```bash
sentinel-src scan-batch \
  --config examples/airsrc-visible-scope.toml \
  --targets examples/airsrc-targets.txt \
  --output-dir runs/airsrc \
  --ack-authorized
```

每个目标会生成独立 JSON，`runs/airsrc/index.json` 保存汇总。可疑项单独在 `suspicious.md` / `suspicious.json`，可提交候选在 `candidates.json`。即使自动化结果存在，也必须逐条人工复现后才能生成或填写提交报告。

定时复扫（默认每小时；可用 `--once` 只跑一轮）：

```bash
sentinel-src watch \
  --config examples/airsrc-visible-scope.toml \
  --targets examples/airsrc-targets.txt \
  --output-dir runs/airsrc \
  --interval 1h \
  --ack-authorized
```

已有扫描结果时，可只重建收件箱：

```bash
sentinel-src inbox --input-dir runs/airsrc
```

`report` 生成的每条发现都带有强制人工补充区：具体系统/功能标题、风险点链接、复现步骤、完整 POC、实际危害和关键截图。`submit` 仍只产生草稿检查包；它不会登录或点击平台的提交按钮。

用户提供的联想 SRC 截图规则已整理到 [policies/lenovo-src.md](policies/lenovo-src.md)。[examples/lenovo-visible-scope.toml](examples/lenovo-visible-scope.toml) 只包含截图中可见的部分域名，使用前必须去官方平台重新确认完整、实时的资产范围。

AirSRC 截图规则整理在 [policies/airsrc.md](policies/airsrc.md)，对应的保守配置为 [examples/airsrc-visible-scope.toml](examples/airsrc-visible-scope.toml)。该配置会过滤平台明确不接收的 CSP 配置缺陷；其他不接收项目前没有主动检查模块，但仍保留在人工核对清单中。

### 双账号权限差分（允许自动化的项目）

复制示例并填入**你自己的**测试账号会话与资源 ID（`auth.local.toml` 已被 gitignore）：

```bash
cp examples/auth.local.example.toml auth.local.toml
cp examples/authz-checks.example.toml authz-checks.toml
# 编辑上述文件后：
sentinel-src authz-compare \
  --config examples/airsrc-visible-scope.toml \
  --auth auth.local.toml \
  --checks authz-checks.toml \
  --output-dir runs/authz \
  --ack-authorized
```

结果写入 `runs/authz/suspicious.md` 与 `candidates.json`。跨账号成功读取且结构指纹接近、且未登录被拒绝时，才会标为可提交候选；仍须你人工复现后再自行交单。

### YZFSRC（禁止自动扫描）

翼支付 YZFSRC 明确禁止自动化扫描，因此 [examples/bestpay-visible-scope.toml](examples/bestpay-visible-scope.toml) 设置了 `automation_allowed = false`。`scan` / `scan-batch` / `watch` / `authz-compare` 都会被拒绝。规则摘录见 [policies/bestpay-yzfsrc.md](policies/bestpay-yzfsrc.md)。

valaSRC 规则整理在 [policies/vala-src.md](policies/vala-src.md)，对应范围配置为 [examples/vala-visible-scope.toml](examples/vala-visible-scope.toml)。配置采用低速单并发，并按截图规则在北京时间 09:00–21:00 阻止批量扫描、`watch` 和 `authz-compare`；人工记录模板见 [templates/vala-manual-review.md](templates/vala-manual-review.md)。

一键自动化（结果写入 `runs/vala/suspicious.md`）：

```bash
sentinel-src auto --program vala --ack-authorized
```

- **09:00–21:00**：自动低速**单轮**扫目标清单（不是批量高频）
- **21:00–09:00**：按批量窗口扫描；加 `--loop` 可持续复扫到早上
- 若仍想白天干等到晚上再扫：加 `--wait`

```bash
sentinel-src auto --program vala --ack-authorized --loop
```

合规路径：浏览器里人工验证 → 填写 [templates/bestpay-manual-review.md](templates/bestpay-manual-review.md) → 可选整理进收件箱：

```bash
sentinel-src scope-check --config examples/bestpay-visible-scope.toml --target https://www.bestpay.cn
sentinel-src inbox-from-manual \
  --input templates/bestpay-manual-review.md \
  --output-dir runs/yzfsrc
```

## 范围语法

- `example.com`：只允许该主机
- `*.example.com`：只允许其子域，不包含根域

默认不允许 IP 字面量、localhost、私网/环回/链路本地地址。`target` 必须使用 HTTPS（除非配置显式开启 `allow_http`）。

## 安全边界

仅可用于你拥有或明确获准测试的资产。不要把它用于批量互联网扫描、绕过认证、暴力破解、社会工程、拒绝服务或破坏性验证。发现可能造成数据访问或状态改变的线索后，应停止自动化并按项目规则人工确认。

