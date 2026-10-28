from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from .taxonomy import SEVERITY_TO_SARIF, annotate_finding, taxonomy_for

REPORT_I18N = {
    "en": {
        "title": "Apocalypse assessment report",
        "doc_title": "Apocalypse report",
        "brand_sub": "Security assessment",
        "target": "Target",
        "status": "Status",
        "profile": "Profile",
        "findings": "Findings",
        "warnings": "Warnings",
        "coverage": "Coverage",
        "endpoints": "unique endpoint(s)",
        "http_crawler": "HTTP crawler",
        "browser_crawler": "browser crawler",
        "baseline": "Baseline",
        "vs": "vs",
        "new": "new",
        "fixed": "fixed",
        "recurring": "recurring",
        "scan_warnings": "Scan warnings",
        "empty": "No findings recorded.",
        "empty_hint": "Completed scans with no rule matches will show an empty list here.",
        "verified": "Verified",
        "url": "URL",
        "reflection": "Reflection context",
        "taxonomy": "Taxonomy",
        "remediation": "Remediation",
        "evidence": "Evidence",
        "lang_zh": "中文",
        "lang_en": "EN",
        "status_queued": "queued",
        "status_running": "running",
        "status_completed": "completed",
        "status_failed": "failed",
    },
    "zh": {
        "title": "Apocalypse 评估报告",
        "doc_title": "Apocalypse 报告",
        "brand_sub": "安全评估",
        "target": "目标",
        "status": "状态",
        "profile": "配置档",
        "findings": "发现",
        "warnings": "警告",
        "coverage": "覆盖",
        "endpoints": "个唯一端点",
        "http_crawler": "HTTP 爬取",
        "browser_crawler": "浏览器爬取",
        "baseline": "基线",
        "vs": "对比",
        "new": "新增",
        "fixed": "已修复",
        "recurring": "复发",
        "scan_warnings": "扫描警告",
        "empty": "暂无漏洞记录。",
        "empty_hint": "扫描完成后若未命中规则，将显示为空列表。",
        "verified": "已验证",
        "url": "URL",
        "reflection": "反射上下文",
        "taxonomy": "分类",
        "remediation": "修复建议",
        "evidence": "证据",
        "lang_zh": "中文",
        "lang_en": "EN",
        "status_queued": "排队中",
        "status_running": "运行中",
        "status_completed": "已完成",
        "status_failed": "失败",
    },
}


def normalize_report_lang(lang: str | None) -> str:
    value = (lang or "en").strip().lower()
    if value.startswith("zh"):
        return "zh"
    return "en"


def lang_from_request(path: str, accept_language: str | None = None) -> str:
    query = parse_qs(urlsplit(path).query)
    if "lang" in query and query["lang"]:
        return normalize_report_lang(query["lang"][0])
    if accept_language:
        primary = accept_language.split(",")[0].strip()
        return normalize_report_lang(primary)
    return "en"


def render_json(scan: dict[str, Any]) -> str:
    annotated = dict(scan)
    findings = [annotate_finding(item) for item in (scan.get("findings_list") or [])]
    annotated["findings_list"] = findings
    return json.dumps(annotated, ensure_ascii=False, indent=2) + "\n"


def render_html(scan: dict[str, Any], *, lang: str | None = None) -> str:
    locale = normalize_report_lang(lang)
    i18n = REPORT_I18N[locale]
    findings = [annotate_finding(item) for item in (scan.get("findings_list") or [])]
    errors = scan.get("errors", [])
    baseline = scan.get("baseline") or {}
    summary = baseline.get("summary") or {}
    scan_id = html.escape(str(scan.get("id") or scan.get("scan_id") or ""))
    status_raw = str(scan.get("status") or "")
    status_label = i18n.get(f"status_{status_raw}", status_raw)
    rows: list[str] = []
    for item in findings:
        evidence = html.escape(json.dumps(item.get("evidence", {}), ensure_ascii=False, indent=2))
        verified = f'<span class="verified">{html.escape(i18n["verified"])}</span>' if item.get("verified") else ""
        context = ""
        reflection = (item.get("evidence") or {}).get("reflection_context")
        if reflection:
            context = (
                f'<p class="meta-line"><span>{html.escape(i18n["reflection"])}</span>'
                f'{html.escape(str(reflection))}</p>'
            )
        tax = ""
        if item.get("cwe") or item.get("owasp"):
            tax = (
                f'<p class="meta-line"><span>{html.escape(i18n["taxonomy"])}</span>'
                f'{html.escape(str(item.get("cwe") or "—"))}'
                f' · {html.escape(str(item.get("owasp") or "—"))}</p>'
            )
        rows.append(f"""
        <article class="finding severity-{html.escape(item['severity'])}">
          <div class="finding-head">
            <span class="sev">{html.escape(item['severity'])}</span>
            {verified}
            <h2>{html.escape(item['title'])}</h2>
          </div>
          <p class="meta-line"><span>{html.escape(i18n['url'])}</span>
            <a href="{html.escape(item['url'])}" target="_blank" rel="noopener">{html.escape(item['url'])}</a></p>
          <p class="desc">{html.escape(item['description'])}</p>
          {tax}
          {context}
          <div class="evidence">
            <div class="evidence-label">{html.escape(i18n['evidence'])}</div>
            <pre>{evidence}</pre>
          </div>
          <p class="meta-line"><span>{html.escape(i18n['remediation'])}</span>
            {html.escape(item['remediation'])}</p>
        </article>""")
    discovered = int(scan.get("discovered") or 0)
    discovered_http = int(scan.get("discovered_http") or 0)
    discovered_browser = int(scan.get("discovered_browser") or 0)
    baseline_block = ""
    if baseline.get("baseline_scan_id"):
        baseline_block = (
            f'<div class="stat"><b>{html.escape(i18n["baseline"])}</b>'
            f'<span>{html.escape(i18n["vs"])} {html.escape(str(baseline["baseline_scan_id"]))}</span>'
            f'<span>{html.escape(i18n["new"])} {int(summary.get("new", 0))}</span>'
            f'<span>{html.escape(i18n["fixed"])} {int(summary.get("fixed", 0))}</span>'
            f'<span>{html.escape(i18n["recurring"])} {int(summary.get("recurring", 0))}</span></div>'
        )
    warnings_block = ""
    if errors:
        warnings_block = (
            f'<section class="card"><h2>{html.escape(i18n["scan_warnings"])}</h2>'
            f'<ul class="warn-list">{"".join(f"<li>{html.escape(str(error))}</li>" for error in errors)}</ul></section>'
        )
    findings_block = "".join(rows) if rows else (
        f'<section class="card empty-card"><p class="empty">{html.escape(i18n["empty"])}</p>'
        f'<p class="empty-hint">{html.escape(i18n["empty_hint"])}</p></section>'
    )
    zh_active = "active" if locale == "zh" else ""
    en_active = "active" if locale == "en" else ""
    return f"""<!doctype html>
<html lang="{'zh-CN' if locale == 'zh' else 'en'}">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>{html.escape(i18n['doc_title'])}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=Outfit:wght@400;500;600;700&family=Syne:wght@600;700;800&display=swap" rel="stylesheet">
  <style>
    :root {{
      --ink:#121a22; --ink-soft:#2f3f4d; --muted:#5a6b79; --line:#c9d4de; --line-soft:#e2e9ef;
      --paper:rgba(255,255,255,.92); --brand:#0f766e; --brand-soft:#ccfbf1; --brand-strong:#0b5f59;
      --ok:#067647; --ok-soft:#ecfdf3; --danger:#b42318; --danger-soft:#fef3f2;
      --warn:#b54708; --warn-soft:#fffaeb; --info:#175cd3; --info-soft:#eff8ff;
      --font:"Outfit","PingFang SC","Hiragino Sans GB","Noto Sans SC",sans-serif;
      --display:"Syne","Outfit","PingFang SC",sans-serif;
      --mono:"IBM Plex Mono",ui-monospace,monospace;
      --shadow:0 1px 0 rgba(16,24,32,.04),0 18px 40px -28px rgba(16,24,32,.35);
    }}
    * {{ box-sizing:border-box; }}
    body {{
      margin:0; min-height:100vh; color:var(--ink); font:15px/1.5 var(--font);
      background:
        radial-gradient(1100px 520px at -8% -18%, rgba(15,118,110,.14), transparent 55%),
        radial-gradient(900px 480px at 110% 0%, rgba(23,92,211,.07), transparent 50%),
        linear-gradient(180deg,#f4f7fa,#e9eef3);
    }}
    main {{ max-width:1080px; margin:0 auto; padding:36px 24px 64px; }}
    .topbar {{ display:flex; justify-content:space-between; align-items:flex-start; gap:16px; margin-bottom:28px; }}
    .brand {{ display:flex; gap:12px; align-items:center; }}
    .brand-mark {{
      width:42px; height:42px; border-radius:12px; display:grid; place-items:center; color:#fff;
      background:linear-gradient(145deg,#14b8a6,#0f766e 55%,#115e59); font:800 20px/1 var(--display);
      box-shadow:inset 0 1px 0 rgba(255,255,255,.25);
    }}
    .brand strong {{ display:block; font:700 22px/1.1 var(--display); letter-spacing:-.03em; }}
    .brand small {{ color:var(--muted); font-size:12.5px; font-weight:500; }}
    h1 {{ margin:18px 0 0; font:700 clamp(28px,3vw,36px)/1.1 var(--display); letter-spacing:-.04em; }}
    .lang {{
      display:inline-flex; gap:2px; padding:3px; border-radius:999px; background:rgba(255,255,255,.75);
      border:1px solid var(--line);
    }}
    .lang a {{
      text-decoration:none; color:var(--muted); padding:7px 12px; border-radius:999px;
      font:650 12px/1 var(--font);
    }}
    .lang a.active {{ background:var(--ink); color:#fff; }}
    .card {{
      background:var(--paper); border:1px solid rgba(18,26,34,.08); border-radius:16px;
      box-shadow:var(--shadow); padding:22px 24px; margin:14px 0; backdrop-filter:blur(10px);
    }}
    .summary-grid {{ display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:12px; margin-top:18px; }}
    .metric {{
      padding:14px 16px; border-radius:12px; background:#f7fafb; border:1px solid var(--line-soft);
    }}
    .metric span {{ display:block; color:var(--muted); font-size:11px; font-weight:700; letter-spacing:.04em; text-transform:uppercase; }}
    .metric strong {{ display:block; margin-top:8px; font:700 22px/1.1 var(--display); letter-spacing:-.03em; }}
    .metric .status-wrap {{ font-size:0; }}
    .metric .status-wrap .pill {{ font-size:13px; padding:6px 10px; }}
    .target {{
      margin:0; font-size:15px; color:var(--ink-soft); word-break:break-all;
    }}
    .target b {{ color:var(--ink); }}
    .pill {{
      display:inline-flex; align-items:center; padding:3px 9px; border-radius:8px;
      font-size:12px; font-weight:700; letter-spacing:.02em;
    }}
    .status-completed {{ color:var(--ok); background:var(--ok-soft); }}
    .status-running,.status-queued {{ color:var(--info); background:var(--info-soft); }}
    .status-failed {{ color:var(--danger); background:var(--danger-soft); }}
    .stat {{ display:flex; flex-wrap:wrap; gap:10px 16px; margin-top:16px; color:var(--ink-soft); font-size:13.5px; }}
    .stat b {{ color:var(--ink); }}
    .card > h2 {{ margin:0 0 12px; font:700 17px/1.2 var(--display); letter-spacing:-.02em; }}
    .warn-list {{ margin:0; padding-left:18px; color:var(--warn); }}
    .empty-card {{ text-align:center; padding:36px 24px; }}
    .empty {{ margin:0; color:var(--muted); font-weight:600; border:1px dashed var(--line); border-radius:12px; padding:28px 18px; background:rgba(255,255,255,.45); }}
    .empty-hint {{ margin:12px 0 0; color:var(--muted); font-size:13px; }}
    .finding {{ border-left:4px solid #94a3b8; }}
    .severity-critical {{ border-left-color:#b42318; }}
    .severity-high {{ border-left-color:#d92d20; }}
    .severity-medium {{ border-left-color:#b54708; }}
    .severity-low {{ border-left-color:#175cd3; }}
    .severity-info {{ border-left-color:#667085; }}
    .finding-head {{ display:flex; flex-wrap:wrap; gap:10px; align-items:center; margin-bottom:10px; }}
    .finding-head h2 {{ margin:0; font:700 17px/1.25 var(--display); letter-spacing:-.02em; }}
    .sev {{
      display:inline-flex; padding:3px 8px; border-radius:8px; font-size:11px; font-weight:750;
      text-transform:uppercase; letter-spacing:.03em; background:#f1f5f9; color:#475569;
    }}
    .severity-critical .sev,.severity-high .sev {{ background:var(--danger-soft); color:var(--danger); }}
    .severity-medium .sev {{ background:var(--warn-soft); color:var(--warn); }}
    .severity-low .sev {{ background:var(--info-soft); color:var(--info); }}
    .verified {{ background:var(--ok-soft); color:var(--ok); border-radius:8px; padding:3px 8px; font-size:11px; font-weight:750; text-transform:uppercase; }}
    .meta-line {{ margin:8px 0; color:var(--ink-soft); }}
    .meta-line span {{ display:inline-block; min-width:5.5em; color:var(--muted); font-weight:650; font-size:12.5px; }}
    .meta-line a {{ color:var(--brand); text-decoration:none; word-break:break-all; }}
    .meta-line a:hover {{ color:var(--brand-strong); }}
    .desc {{ margin:10px 0; color:var(--ink); }}
    .evidence {{ margin:12px 0; }}
    .evidence-label {{ font-size:12px; font-weight:700; color:var(--muted); margin-bottom:6px; letter-spacing:.03em; text-transform:uppercase; }}
    pre {{
      margin:0; white-space:pre-wrap; word-break:break-word; background:#f3f7f8; border:1px solid var(--line-soft);
      border-radius:10px; padding:12px; font:12px/1.45 var(--mono); color:var(--ink-soft);
    }}
    @media (max-width:800px) {{
      .summary-grid {{ grid-template-columns:repeat(2,minmax(0,1fr)); }}
      .topbar {{ flex-direction:column; }}
    }}
    @media (max-width:520px) {{
      .summary-grid {{ grid-template-columns:1fr; }}
    }}
  </style>
</head>
<body>
  <main>
    <div class="topbar">
      <div>
        <div class="brand">
          <span class="brand-mark">A</span>
          <div><strong>Apocalypse</strong><small>{html.escape(i18n['brand_sub'])}</small></div>
        </div>
        <h1>{html.escape(i18n['title'])}</h1>
      </div>
      <div class="lang" role="group" aria-label="Language">
        <a class="{zh_active}" href="/reports/{scan_id}.html?lang=zh">{html.escape(i18n['lang_zh'])}</a>
        <a class="{en_active}" href="/reports/{scan_id}.html?lang=en">{html.escape(i18n['lang_en'])}</a>
      </div>
    </div>

    <section class="card">
      <p class="target"><b>{html.escape(i18n['target'])}</b> · {html.escape(scan['target'])}</p>
      <div class="summary-grid">
        <div class="metric"><span>{html.escape(i18n['status'])}</span><strong class="status-wrap"><em class="pill status-{html.escape(status_raw)}">{html.escape(status_label)}</em></strong></div>
        <div class="metric"><span>{html.escape(i18n['profile'])}</span><strong>{html.escape(str(scan.get('profile') or ''))}</strong></div>
        <div class="metric"><span>{html.escape(i18n['findings'])}</span><strong>{len(findings)}</strong></div>
        <div class="metric"><span>{html.escape(i18n['warnings'])}</span><strong>{len(errors)}</strong></div>
      </div>
      <div class="stat">
        <b>{html.escape(i18n['coverage'])}</b>
        <span>{discovered} {html.escape(i18n['endpoints'])}</span>
        <span>{html.escape(i18n['http_crawler'])} {discovered_http}</span>
        <span>{html.escape(i18n['browser_crawler'])} {discovered_browser}</span>
      </div>
      {baseline_block}
    </section>
    {warnings_block}
    {findings_block}
  </main>
</body>
</html>"""


def render_sarif(scan: dict[str, Any]) -> str:
    """Emit SARIF 2.1.0 for CI systems (GitHub code scanning compatible shape)."""
    findings = [annotate_finding(item) for item in (scan.get("findings_list") or [])]
    rules_by_id: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for item in findings:
        rule_id = str(item.get("rule_id") or "apocalypse.finding")
        tax = taxonomy_for(rule_id)
        if rule_id not in rules_by_id:
            properties: dict[str, Any] = {"severity": item.get("severity"), "category": item.get("category")}
            if tax.get("cwe"):
                properties["security-severity"] = item.get("severity")
                properties["tags"] = [tax["cwe"], tax.get("owasp") or ""]
            rules_by_id[rule_id] = {
                "id": rule_id,
                "name": item.get("title") or rule_id,
                "shortDescription": {"text": item.get("title") or rule_id},
                "fullDescription": {"text": item.get("description") or ""},
                "help": {"text": item.get("remediation") or "", "markdown": item.get("remediation") or ""},
                "properties": properties,
                "defaultConfiguration": {"level": SEVERITY_TO_SARIF.get(str(item.get("severity")), "note")},
            }
            if tax.get("cwe"):
                rules_by_id[rule_id]["relationships"] = [{
                    "target": {
                        "id": tax["cwe"],
                        "toolComponent": {"name": "CWE"},
                    },
                    "kinds": ["superset"],
                }]
        results.append({
            "ruleId": rule_id,
            "level": SEVERITY_TO_SARIF.get(str(item.get("severity")), "note"),
            "message": {"text": f"{item.get('title')}: {item.get('description')}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": item.get("url") or scan.get("target")},
                }
            }],
            "properties": {
                "confidence": item.get("confidence"),
                "verified": bool(item.get("verified")),
                "cwe": tax.get("cwe"),
                "owasp": tax.get("owasp"),
                "evidence": item.get("evidence") or {},
            },
        })
    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Apocalypse",
                    "informationUri": "https://github.com/",
                    "rules": list(rules_by_id.values()),
                }
            },
            "results": results,
            "properties": {
                "scan_id": scan.get("id") or scan.get("scan_id"),
                "target": scan.get("target"),
                "profile": scan.get("profile"),
                "status": scan.get("status"),
            },
        }],
    }
    return json.dumps(document, ensure_ascii=False, indent=2) + "\n"


def write_report(scan: dict[str, Any], output: Path, fmt: str, *, lang: str | None = None) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "html":
        body = render_html(scan, lang=lang)
    elif fmt == "sarif":
        body = render_sarif(scan)
    else:
        body = render_json(scan)
    output.write_text(body, encoding="utf-8")
