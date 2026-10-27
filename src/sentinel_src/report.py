from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_result(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def markdown_report(data: dict[str, Any]) -> str:
    findings = data.get("findings", [])
    parts = [
        "# 授权安全检测报告\n",
        f"- 目标：`{data.get('target', '')}`\n",
        f"- 扫描时间：{data.get('started_at', '')}\n",
        f"- 发现数量：{len(findings)}\n",
        f"- 可提交候选：{sum(1 for finding in findings if finding.get('submittable', False))}\n",
        f"- 待人工分流/加固项：{sum(1 for finding in findings if not finding.get('submittable', False))}\n",
        "\n> 自动化结果仅供初筛，不可直接提交。必须人工复现、确认影响、补齐 POC 与截图，并重新核对平台实时范围。\n",
    ]
    for index, finding in enumerate(findings, 1):
        evidence = json.dumps(finding.get("evidence", {}), ensure_ascii=False, indent=2)
        parts.extend([
            f"\n## {index}. 【待补具体系统/功能】{finding.get('title', '未命名发现')}\n",
            f"- 严重性：{finding.get('severity', 'unknown')}\n",
            f"- 置信度：{finding.get('confidence', 'unknown')}\n",
            f"- URL：`{finding.get('url', '')}`\n",
            f"- 可提交候选：{'是' if finding.get('submittable', False) else '否'}\n",
            f"- 分流原因：{finding.get('triage_reason', '需要人工判断')}\n",
            f"\n{finding.get('description', '')}\n",
            "\n### 证据\n\n```json\n", evidence, "\n```\n",
            f"\n### 修复建议\n\n{finding.get('remediation', '')}\n",
            "\n### 风险点链接\n\n",
            f"{finding.get('url', '')}\n",
            "\n### 人工复现步骤\n\n<!-- 必填：逐步写出可复现、无破坏性的操作；不得上传 WebShell。 -->\n",
            "\n1. \n2. \n3. \n",
            "\n### 完整 POC\n\n<!-- 必填：仅保留验证漏洞所需的最小请求/响应，先脱敏。 -->\n",
            "\n### 实际危害\n\n<!-- 必填：描述已人工验证的实际业务影响，不能照抄自动化推测。 -->\n",
            "\n### 关键步骤与结果截图\n\n<!-- 必填：插入本地截图或平台附件编号；截图需显示 URL、关键步骤和结果。 -->\n",
            "\n### 人工验证声明\n\n",
            "- [ ] 我已亲自复现该问题，确认不是 AI 幻觉或扫描器误报。\n",
            "- [ ] 目标、风险点 URL 和测试行为均在项目实时授权范围内。\n",
            "- [ ] POC 未读取、修改或泄露非必要数据，且未上传 WebShell。\n",
        ])
    return "".join(parts)


def _is_suspicious(finding: dict[str, Any]) -> bool:
    return bool(finding.get("submittable") or finding.get("suspicious"))


def select_candidates(data: dict[str, Any]) -> list[dict[str, Any]]:
    return [finding for finding in data.get("findings", []) if finding.get("submittable", False)]


def select_suspicious(data: dict[str, Any]) -> list[dict[str, Any]]:
    return [finding for finding in data.get("findings", []) if _is_suspicious(finding)]


def submission_bundle(data: dict[str, Any]) -> dict[str, Any]:
    candidates = select_candidates(data)
    return {
        "status": "draft_requires_human_review",
        "target": data.get("target"),
        "findings": candidates,
        "excluded_noise_count": len(data.get("findings", [])) - len(candidates),
        "checklist": [
            "已在提交当日重新核对平台公告，目标和风险点 URL 均在授权范围内",
            "标题明确写出具体系统或功能与漏洞类型",
            "已人工复现且不是 AI 幻觉或扫描器误报",
            "已提供可复制的实际风险点链接",
            "已提供详细复现步骤、完整 POC、关键步骤及结果截图",
            "证据不包含用户数据、令牌或其他秘密",
            "严重性与实际业务影响匹配",
            "验证过程未上传 WebShell，未破坏系统或侵害用户权益",
            "提交内容符合 SRC 项目规则",
        ],
        "platform_submission_enabled": False,
        "submission_note": "此文件仅为草稿。完成全部人工验证并在平台页面逐项填写后方可提交。",
    }


def build_inbox(results: list[dict[str, Any]], *, generated_at: str) -> dict[str, Any]:
    """Aggregate suspicious / submittable findings across one or more scan results."""
    suspicious_items: list[dict[str, Any]] = []
    candidate_items: list[dict[str, Any]] = []
    for data in results:
        target = data.get("target", "")
        source = data.get("output") or data.get("source") or ""
        for finding in select_suspicious(data):
            item = dict(finding)
            item["target"] = target
            if source:
                item["source"] = source
            suspicious_items.append(item)
            if finding.get("submittable"):
                candidate_items.append(item)
    return {
        "generated_at": generated_at,
        "status": "human_review_inbox",
        "target_count": len(results),
        "suspicious_count": len(suspicious_items),
        "candidate_count": len(candidate_items),
        "suspicious": suspicious_items,
        "candidates": candidate_items,
        "note": "suspicious 需人工复核；candidates 为工具标记可提交候选，仍须人工复现后才能正式提交。",
    }


def suspicious_markdown(inbox: dict[str, Any]) -> str:
    items = inbox.get("suspicious", [])
    parts = [
        "# 可疑发现收件箱\n\n",
        f"- 生成时间：{inbox.get('generated_at', '')}\n",
        f"- 可疑条数：{inbox.get('suspicious_count', 0)}\n",
        f"- 可提交候选：{inbox.get('candidate_count', 0)}\n",
        "\n> 此列表仅供人工复核，不会自动提交到 SRC。\n",
    ]
    if not items:
        parts.append("\n当前没有可疑项。\n")
        return "".join(parts)
    for index, finding in enumerate(items, 1):
        evidence = json.dumps(finding.get("evidence", {}), ensure_ascii=False, indent=2)
        parts.extend([
            f"\n## {index}. {finding.get('title', '未命名发现')}\n",
            f"- 目标：`{finding.get('target', '')}`\n",
            f"- URL：`{finding.get('url', '')}`\n",
            f"- 严重性：{finding.get('severity', 'unknown')}\n",
            f"- 可提交候选：{'是' if finding.get('submittable') else '否'}\n",
            f"- 分流原因：{finding.get('triage_reason', '')}\n",
            f"\n{finding.get('description', '')}\n",
            "\n```json\n", evidence, "\n```\n",
        ])
    return "".join(parts)


def collect_run_results(output_dir: Path) -> list[dict[str, Any]]:
    """Load per-target JSON results from a batch/watch output directory."""
    results: list[dict[str, Any]] = []
    index_path = output_dir / "index.json"
    if index_path.exists():
        index = load_result(index_path)
        for entry in index.get("targets", []):
            rel = entry.get("output")
            if not rel:
                continue
            path = Path(str(rel))
            if not path.is_absolute():
                # Prefer file inside output_dir when basename matches.
                local = output_dir / path.name
                path = local if local.exists() else path
            if path.exists():
                data = load_result(path)
                data["output"] = str(path)
                results.append(data)
        if results:
            return results
    for path in sorted(output_dir.glob("*.json")):
        if path.name in {"index.json", "suspicious.json", "candidates.json", "watch-state.json"}:
            continue
        data = load_result(path)
        if "findings" not in data:
            continue
        data["output"] = str(path)
        results.append(data)
    return results

