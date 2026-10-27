from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from .authz import (
    AuthzComparer,
    load_auth_file,
    load_authz_checks,
    parse_manual_review,
    render_check_url,
)
from .batch import load_targets, result_filename
from .config import ScanConfig
from .programs import PROGRAMS, resolve_targets_file
from .report import (
    build_inbox,
    collect_run_results,
    load_result,
    markdown_report,
    submission_bundle,
    suspicious_markdown,
)
from .scanner import Scanner

AUTOMATION_BLOCKED = (
    "blocked: this program prohibits automated scanning; no request was sent. "
    "Use 'scope-check', templates/bestpay-manual-review.md, or 'inbox-from-manual' instead."
)


def _write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _require_automation(config: ScanConfig, *, bulk: bool = False) -> None:
    if not config.automation_allowed:
        print(AUTOMATION_BLOCKED, file=sys.stderr)
        raise SystemExit(2)
    if bulk and config.bulk_automation_blocked():
        start, end = config.blocked_bulk_hours or (0, 0)
        print(
            f"blocked: bulk automation is disabled from {start:02d}:00 to {end:02d}:00 "
            f"in {config.automation_timezone}; no request was sent.",
            file=sys.stderr,
        )
        raise SystemExit(2)


def parse_interval(value: str) -> int:
    """Parse 30s / 5m / 1h / 1d or plain seconds into an integer second count."""
    text = value.strip().lower()
    match = re.fullmatch(r"(\d+)([smhd])?", text)
    if not match:
        raise argparse.ArgumentTypeError("interval must look like 300, 30s, 5m, 1h, or 1d")
    amount = int(match.group(1))
    unit = match.group(2) or "s"
    multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    seconds = amount * multipliers[unit]
    if seconds < 60:
        raise argparse.ArgumentTypeError("interval must be at least 60 seconds")
    if seconds > 7 * 86400:
        raise argparse.ArgumentTypeError("interval must be at most 7 days")
    return seconds


def write_inbox(output_dir: Path, results: list[dict[str, object]]) -> dict[str, object]:
    inbox = build_inbox(results, generated_at=_now_iso())
    _write_json(output_dir / "suspicious.json", {
        "generated_at": inbox["generated_at"],
        "status": inbox["status"],
        "suspicious_count": inbox["suspicious_count"],
        "findings": inbox["suspicious"],
        "note": inbox["note"],
    })
    _write_json(output_dir / "candidates.json", {
        "generated_at": inbox["generated_at"],
        "status": "submittable_candidates",
        "candidate_count": inbox["candidate_count"],
        "findings": inbox["candidates"],
        "note": "仅含 submittable=true 的条目；提交前仍须人工复现。",
    })
    (output_dir / "suspicious.md").write_text(suspicious_markdown(inbox), encoding="utf-8")
    return inbox


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sentinel-src", description="Authorized, scope-safe SRC checks")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="run low-risk checks against one authorized target")
    scan.add_argument("--config", type=Path, required=True)
    scan.add_argument("--target", required=True)
    scan.add_argument("--output", type=Path, default=Path("runs/latest.json"))

    scope_check = sub.add_parser("scope-check", help="validate one URL against a program scope without network access")
    scope_check.add_argument("--config", type=Path, required=True)
    scope_check.add_argument("--target", required=True)

    batch = sub.add_parser("scan-batch", help="scan an explicit, authorized target manifest")
    batch.add_argument("--config", type=Path, required=True)
    batch.add_argument("--targets", type=Path, required=True, help="one complete URL per line; no discovery")
    batch.add_argument("--output-dir", type=Path, default=Path("runs/batch"))
    batch.add_argument(
        "--ack-authorized", action="store_true", required=True,
        help="confirm every URL was checked against the program's current authorized scope",
    )

    watch = sub.add_parser("watch", help="periodically rescan targets and refresh the suspicious inbox")
    watch.add_argument("--config", type=Path, required=True)
    watch.add_argument("--targets", type=Path, required=True)
    watch.add_argument("--output-dir", type=Path, default=Path("runs/watch"))
    watch.add_argument("--interval", type=parse_interval, default="1h", help="e.g. 30m, 1h, 6h (min 60s)")
    watch.add_argument("--once", action="store_true", help="run a single cycle and exit")
    watch.add_argument(
        "--ack-authorized", action="store_true", required=True,
        help="confirm every URL was checked against the program's current authorized scope",
    )

    authz = sub.add_parser("authz-compare", help="dual-account GET authorization differential checks")
    authz.add_argument("--config", type=Path, required=True)
    authz.add_argument("--auth", type=Path, required=True, help="auth.local.toml with account_a / account_b")
    authz.add_argument("--checks", type=Path, required=True, help="[[checks]] manifest with {id} URLs")
    authz.add_argument("--output-dir", type=Path, default=Path("runs/authz"))
    authz.add_argument(
        "--ack-authorized", action="store_true", required=True,
        help="confirm accounts and resource IDs are owned/permitted and in current program scope",
    )

    inbox = sub.add_parser("inbox", help="rebuild suspicious/candidates lists from an existing run directory")
    inbox.add_argument("--input-dir", type=Path, required=True)

    manual = sub.add_parser(
        "inbox-from-manual",
        help="import a filled manual review markdown into suspicious inbox (no network)",
    )
    manual.add_argument("--input", type=Path, required=True, help="filled templates/bestpay-manual-review.md or similar")
    manual.add_argument("--output-dir", type=Path, default=Path("runs/manual-inbox"))

    report = sub.add_parser("report", help="render a Markdown report")
    report.add_argument("--input", type=Path, required=True)
    report.add_argument("--output", type=Path, required=True)

    submit = sub.add_parser("submit", help="create a human-review submission bundle")
    submit.add_argument("--input", type=Path, required=True)
    submit.add_argument("--output", type=Path, required=True)

    auto = sub.add_parser(
        "auto",
        help="one-command program automation (day: one low-speed round; night: bulk / optional loop)",
    )
    auto.add_argument(
        "--program",
        required=True,
        choices=sorted(PROGRAMS),
        help="preset program profile, e.g. vala",
    )
    auto.add_argument(
        "--ack-authorized",
        action="store_true",
        required=True,
        help="confirm targets were checked against the program's current authorized scope",
    )
    auto.add_argument(
        "--loop",
        action="store_true",
        help="after night bulk starts, keep rescanning until the bulk window closes",
    )
    auto.add_argument(
        "--wait",
        action="store_true",
        help="during blocked bulk hours, wait for the night window instead of doing a day single-round scan",
    )
    return parser


def _load_program_targets(config: ScanConfig, program: str) -> list[str]:
    preset = PROGRAMS[program]
    path = resolve_targets_file(preset)
    if path is not None:
        try:
            return load_targets(path, config)
        except ValueError:
            # example file may contain only comments
            pass
    if not preset.default_targets:
        raise SystemExit(
            f"no targets found; create {preset.targets} with one https URL per line "
            f"(see {preset.targets.parent / (preset.targets.stem + '.example.txt')})"
        )
    print(f"[auto] using built-in default target(s) for {program}; prefer maintaining {preset.targets}")
    for target in preset.default_targets:
        config.scope.validate_url(target, resolve_dns=False)
    return list(preset.default_targets)


async def _wait_for_bulk_window(config: ScanConfig) -> None:
    while config.bulk_automation_blocked():
        delay = config.seconds_until_bulk_allowed()
        if delay <= 0:
            delay = 60
        hours = delay / 3600
        print(
            f"[auto] bulk window closed in {config.automation_timezone}; "
            f"sleeping ~{hours:.1f}h until open (Ctrl+C to stop)"
        )
        await asyncio.sleep(min(delay, 3600))


async def _auto_day_round(config: ScanConfig, targets: list[str], output_dir: Path) -> None:
    """One low-speed pass over targets during hours when bulk automation is blocked."""
    print(f"[auto] daytime single-round: {len(targets)} target(s), low-speed sequential scan")
    try:
        await _scan_batch(config, targets, output_dir)
    except Exception as exc:  # noqa: BLE001 - surface network/scope failures cleanly
        print(f"[auto] day scan failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
    print(f"[auto] day round complete -> {output_dir / 'suspicious.md'}")


async def _auto_program(program: str, *, loop: bool, wait_for_night: bool) -> None:
    preset = PROGRAMS[program]
    print(f"[auto] program={program}")
    if preset.note:
        print(f"[auto] {preset.note}")
    if not preset.config.exists():
        raise SystemExit(f"missing config: {preset.config}")
    config = ScanConfig.load(preset.config)
    _require_automation(config)
    targets = _load_program_targets(config, program)
    output_dir = preset.output_dir

    if config.bulk_automation_blocked():
        if wait_for_night:
            await _wait_for_bulk_window(config)
        else:
            await _auto_day_round(config, targets, output_dir)
            if not loop:
                return
            print("[auto] --loop requested: waiting for night bulk window before continuous rescans")
            await _wait_for_bulk_window(config)

    _require_automation(config, bulk=True)
    await _scan_batch(config, targets, output_dir)
    print(f"[auto] night bulk complete -> {output_dir / 'suspicious.md'}")

    if not loop:
        return

    interval = parse_interval(preset.interval)
    print(f"[auto] looping every {preset.interval} until bulk window closes")
    while True:
        if config.bulk_automation_blocked():
            print("[auto] bulk window closed; stopping loop")
            return
        print(f"[auto] sleeping {interval}s before next cycle")
        await asyncio.sleep(interval)
        if config.bulk_automation_blocked():
            print("[auto] bulk window closed; stopping loop")
            return
        await _scan_batch(config, targets, output_dir)


async def _scan_batch(config: ScanConfig, targets: list[str], output_dir: Path) -> dict[str, object]:
    output_dir.mkdir(parents=True, exist_ok=True)
    scanner = Scanner(config)
    entries: list[dict[str, object]] = []
    result_payloads: list[dict[str, object]] = []
    for target in targets:
        result = await scanner.scan(target)
        output = output_dir / result_filename(target)
        payload = result.to_dict()
        _write_json(output, payload)
        payload_with_source = dict(payload)
        payload_with_source["output"] = str(output)
        result_payloads.append(payload_with_source)
        suspicious = sum(1 for finding in result.findings if finding.suspicious or finding.submittable)
        candidates = sum(1 for finding in result.findings if finding.submittable)
        noise = len(result.findings) - suspicious
        entries.append({
            "target": target,
            "output": str(output),
            "finding_count": len(result.findings),
            "error_count": len(result.errors),
            "candidate_count": candidates,
            "suspicious_count": suspicious,
            "noise_count": noise,
            "scanned_url_count": len(result.scanned_urls),
        })
        print(
            f"scanned {target}: {candidates} candidate(s), "
            f"{suspicious} suspicious, {noise} noise, {len(result.errors)} error(s)"
        )
    index: dict[str, object] = {
        "status": "automated_triage_requires_human_review",
        "generated_at": _now_iso(),
        "target_count": len(entries),
        "targets": entries,
    }
    _write_json(output_dir / "index.json", index)
    inbox = write_inbox(output_dir, result_payloads)
    index["suspicious_count"] = inbox["suspicious_count"]
    index["candidate_count"] = inbox["candidate_count"]
    _write_json(output_dir / "index.json", index)
    if inbox["suspicious_count"]:
        print(
            f"ALERT: {inbox['suspicious_count']} suspicious finding(s) -> "
            f"{output_dir / 'suspicious.md'}"
        )
    else:
        print(f"no suspicious findings; inbox cleared at {output_dir / 'suspicious.md'}")
    return index


async def _authz_compare(
    config: ScanConfig,
    auth_path: Path,
    checks_path: Path,
    output_dir: Path,
) -> dict[str, object]:
    output_dir.mkdir(parents=True, exist_ok=True)
    account_a, account_b = load_auth_file(auth_path)
    checks = load_authz_checks(checks_path)
    for check in checks:
        config.scope.validate_url(render_check_url(check.url_template, check.id_a), resolve_dns=False)
        config.scope.validate_url(render_check_url(check.url_template, check.id_b), resolve_dns=False)
    comparer = AuthzComparer(config, account_a, account_b)
    result = await comparer.run(checks)
    output = output_dir / "authz-compare.json"
    payload = result.to_dict()
    _write_json(output, payload)
    payload_with_source = dict(payload)
    payload_with_source["output"] = str(output)
    inbox = write_inbox(output_dir, [payload_with_source])
    index = {
        "status": "authz_compare_requires_human_review",
        "generated_at": _now_iso(),
        "target": result.target,
        "checks_run": result.checks_run,
        "finding_count": len(result.findings),
        "error_count": len(result.errors),
        "candidate_count": inbox["candidate_count"],
        "suspicious_count": inbox["suspicious_count"],
        "output": str(output),
    }
    _write_json(output_dir / "index.json", index)
    print(
        f"authz-compare: {inbox['candidate_count']} candidate(s), "
        f"{inbox['suspicious_count']} suspicious, {len(result.errors)} error(s)"
    )
    if inbox["suspicious_count"]:
        print(f"ALERT: review {output_dir / 'suspicious.md'}")
    return index


async def _watch_loop(
    config: ScanConfig,
    targets: list[str],
    output_dir: Path,
    interval: int,
    once: bool,
) -> None:
    cycle = 0
    while True:
        _require_automation(config, bulk=True)
        cycle += 1
        started = _now_iso()
        print(f"[watch] cycle {cycle} started at {started}")
        index = await _scan_batch(config, targets, output_dir)
        state = {
            "last_cycle": cycle,
            "last_started_at": started,
            "last_finished_at": _now_iso(),
            "interval_seconds": interval,
            "suspicious_count": index.get("suspicious_count", 0),
            "candidate_count": index.get("candidate_count", 0),
            "index": str(output_dir / "index.json"),
            "suspicious": str(output_dir / "suspicious.json"),
            "candidates": str(output_dir / "candidates.json"),
        }
        _write_json(output_dir / "watch-state.json", state)
        if once:
            return
        print(f"[watch] sleeping {interval}s until next cycle (Ctrl+C to stop)")
        await asyncio.sleep(interval)


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if args.command == "scan":
        config = ScanConfig.load(args.config)
        _require_automation(config)
        result = asyncio.run(Scanner(config).scan(args.target))
        payload = result.to_dict()
        _write_json(args.output, payload)
        suspicious = sum(1 for finding in result.findings if finding.suspicious or finding.submittable)
        print(
            f"saved {len(result.findings)} finding(s) "
            f"({suspicious} suspicious) to {args.output}"
        )
    elif args.command == "scope-check":
        config = ScanConfig.load(args.config)
        try:
            host = config.scope.validate_url(args.target, resolve_dns=False)
        except ValueError as exc:
            print(f"out of scope: {exc}", file=sys.stderr)
            raise SystemExit(2) from exc
        mode = "manual testing only" if not config.automation_allowed else "automation permitted by local config"
        print(f"in configured scope: {host} ({mode}; no network request sent)")
    elif args.command == "scan-batch":
        config = ScanConfig.load(args.config)
        _require_automation(config, bulk=True)
        targets = load_targets(args.targets, config)
        asyncio.run(_scan_batch(config, targets, args.output_dir))
        print(f"saved batch index to {args.output_dir / 'index.json'}")
    elif args.command == "watch":
        config = ScanConfig.load(args.config)
        _require_automation(config, bulk=True)
        targets = load_targets(args.targets, config)
        try:
            asyncio.run(_watch_loop(config, targets, args.output_dir, args.interval, args.once))
        except KeyboardInterrupt:
            print("\n[watch] stopped")
    elif args.command == "authz-compare":
        config = ScanConfig.load(args.config)
        _require_automation(config, bulk=True)
        asyncio.run(_authz_compare(config, args.auth, args.checks, args.output_dir))
        print(f"saved authz inbox to {args.output_dir / 'suspicious.md'}")
    elif args.command == "inbox":
        results = collect_run_results(args.input_dir)
        if not results:
            raise SystemExit(f"no scan results found in {args.input_dir}")
        inbox = write_inbox(args.input_dir, results)
        print(
            f"inbox: {inbox['suspicious_count']} suspicious, "
            f"{inbox['candidate_count']} candidate(s) -> {args.input_dir / 'suspicious.md'}"
        )
    elif args.command == "inbox-from-manual":
        payload = parse_manual_review(args.input)
        args.output_dir.mkdir(parents=True, exist_ok=True)
        output = args.output_dir / "manual-finding.json"
        _write_json(output, payload)
        payload_with_source = dict(payload)
        payload_with_source["output"] = str(output)
        inbox = write_inbox(args.output_dir, [payload_with_source])
        print(
            f"manual inbox: {inbox['suspicious_count']} suspicious, "
            f"{inbox['candidate_count']} candidate(s) -> {args.output_dir / 'suspicious.md'} "
            "(no network request sent)"
        )
    elif args.command == "report":
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(markdown_report(load_result(args.input)), encoding="utf-8")
        print(f"saved report to {args.output}")
    elif args.command == "auto":
        try:
            asyncio.run(
                _auto_program(
                    args.program,
                    loop=args.loop,
                    wait_for_night=args.wait,
                )
            )
        except KeyboardInterrupt:
            print("\n[auto] stopped")
    else:
        _write_json(args.output, submission_bundle(load_result(args.input)))
        print(f"saved draft submission bundle to {args.output}")


if __name__ == "__main__":
    main()
