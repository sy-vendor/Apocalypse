from __future__ import annotations

import argparse
import asyncio
import json
import secrets
import sys
from pathlib import Path

from . import __version__
from .baseline import compare_findings
from .campaign import CampaignSpec, create_campaign, run_campaign
from .engine import FAIL_ON_LEVELS, PROFILES, ScanEngine, parse_header_lines, should_fail
from .login import example_login_flow, load_login_flow, record_login_interactively
from .models import ScanOptions, now_iso
from .oast import validate_oast_base
from .policy import example_policy, load_policy
from .reporting import write_report
from .schedule import create_schedule
from .sso import tenant_slug, validate_oidc_config
from .storage import Storage
from .team import create_user_record
from .tickets import validate_ticket_config
from .web import serve
from .webhook import validate_webhook_url


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="apocalypse", description="Authorized web vulnerability assessment platform")
    parser.add_argument("--db", type=Path, default=Path("data/apocalypse.db"), help="SQLite database path")
    parser.add_argument("--version", action="version", version=f"Apocalypse {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="run one authorized assessment")
    scan.add_argument("--target", required=True)
    scan.add_argument("--profile", choices=sorted(PROFILES), default="safe")
    scan.add_argument("--allow-private", action="store_true", help="allow private/local destinations for an owned lab")
    scan.add_argument(
        "--header", action="append", default=[], metavar="'NAME: VALUE'",
        help="ephemeral request header, for example Authorization or Cookie (repeatable)",
    )
    scan.add_argument(
        "--submit-forms", action="store_true",
        help="allow bounded non-password POST form canaries (deep profile only)",
    )
    scan.add_argument(
        "--blind-inject", action="store_true",
        help="enable bounded boolean/time-based SQLi heuristics (deep profile only)",
    )
    scan.add_argument(
        "--openapi-url", help="same-scope OpenAPI/Swagger JSON URL used to seed read-only API discovery",
    )
    scan.add_argument(
        "--browser-crawl", action="store_true",
        help="use optional headless Chromium discovery for rendered DOM and Fetch/XHR endpoints",
    )
    scan.add_argument(
        "--login-flow", type=Path,
        help="JSON login recording replayed in Chromium before crawling (secrets via ${ENV})",
    )
    scan.add_argument("--graphql", action="store_true", help="probe common same-origin GraphQL paths with introspection")
    scan.add_argument("--graphql-url", help="explicit same-scope GraphQL endpoint for introspection")
    scan.add_argument("--webhook", help="POST a secret-free completion payload to this URL")
    scan.add_argument(
        "--fail-on", choices=sorted(FAIL_ON_LEVELS), default="none",
        help="CI exit code 1 when findings reach this severity or higher",
    )
    scan.add_argument(
        "--no-api-probe", action="store_true",
        help="disable OpenAPI/JSON/GraphQL argument active probing",
    )
    scan.add_argument(
        "--oast-url",
        help="out-of-band collaborator base URL (supports GET {base}/poll/{token})",
    )
    scan.add_argument(
        "--oast-listen", metavar="HOST:PORT",
        help="start a loopback OAST listener for lab SSRF corroboration (e.g. 127.0.0.1:0)",
    )
    scan.add_argument(
        "--secondary-header", action="append", default=[], metavar="'NAME: VALUE'",
        help="second session header for IDOR/BOLA differentials (repeatable)",
    )
    scan.add_argument(
        "--browser-verify", action="store_true",
        help="confirm reflected XSS candidates in Chromium (dialog canary)",
    )
    scan.add_argument("--policy", type=Path, help="JSON scan policy (disabled rules / path / param excludes)")
    scan.add_argument("--ack-authorized", action="store_true", required=True)

    ui = sub.add_parser("serve", help="start the local web console")
    ui.add_argument("--host", default="127.0.0.1")
    ui.add_argument("--port", type=int, default=8080)
    ui.add_argument("--allow-remote-ui", action="store_true", help="acknowledge risks of binding beyond loopback")
    ui.add_argument("--no-scheduler", action="store_true", help="disable background schedule runner")

    schedule = sub.add_parser("schedule", help="manage recurring authorized scans")
    schedule_sub = schedule.add_subparsers(dest="schedule_command", required=True)
    schedule_add = schedule_sub.add_parser("add", help="add a recurring scan")
    schedule_add.add_argument("--target", required=True)
    schedule_add.add_argument("--profile", choices=sorted(PROFILES), default="safe")
    schedule_add.add_argument("--every", type=int, required=True, metavar="MINUTES", help="interval in minutes (>=5)")
    schedule_add.add_argument("--allow-private", action="store_true")
    schedule_add.add_argument("--openapi-url")
    schedule_add.add_argument("--browser-crawl", action="store_true")
    schedule_add.add_argument("--graphql", action="store_true")
    schedule_add.add_argument("--graphql-url")
    schedule_add.add_argument("--webhook")
    schedule_add.add_argument("--ack-authorized", action="store_true", required=True)
    schedule_sub.add_parser("list", help="list schedules")
    schedule_remove = schedule_sub.add_parser("remove", help="remove a schedule")
    schedule_remove.add_argument("schedule_id")

    login = sub.add_parser("login-template", help="print an example login-flow JSON")
    login.add_argument("--output", type=Path)

    policy_cmd = sub.add_parser("policy-template", help="print an example scan policy JSON")
    policy_cmd.add_argument("--output", type=Path)

    login_record = sub.add_parser("login-record", help="interactive Chromium click-to-record login flow")
    login_record.add_argument("--start-url", required=True)
    login_record.add_argument("--output", type=Path, required=True)
    login_record.add_argument("--timeout", type=int, default=300, help="seconds to wait for Done (30-1800)")
    login_record.add_argument("--headless", action="store_true", help="run recorder without a visible window")

    campaign = sub.add_parser("campaign", help="multi-target scan orchestration")
    campaign_sub = campaign.add_subparsers(dest="campaign_command", required=True)
    campaign_create = campaign_sub.add_parser("create", help="create a campaign from a target list file")
    campaign_create.add_argument("--name", default="campaign")
    campaign_create.add_argument("--targets-file", type=Path, required=True)
    campaign_create.add_argument("--profile", choices=sorted(PROFILES), default="safe")
    campaign_create.add_argument("--concurrency", type=int, default=2)
    campaign_create.add_argument("--allow-private", action="store_true")
    campaign_create.add_argument("--browser-crawl", action="store_true")
    campaign_create.add_argument("--graphql", action="store_true")
    campaign_create.add_argument("--blind-inject", action="store_true")
    campaign_create.add_argument("--webhook")
    campaign_create.add_argument("--ack-authorized", action="store_true", required=True)
    campaign_run = campaign_sub.add_parser("run", help="run a queued campaign")
    campaign_run.add_argument("campaign_id")
    campaign_sub.add_parser("list", help="list campaigns")
    campaign_show = campaign_sub.add_parser("show", help="show one campaign")
    campaign_show.add_argument("campaign_id")

    user = sub.add_parser("user", help="manage local team API users")
    user_sub = user.add_subparsers(dest="user_command", required=True)
    user_add = user_sub.add_parser("add", help="create a user and print a one-time API token")
    user_add.add_argument("--name", required=True)
    user_add.add_argument("--role", choices=("admin", "analyst", "viewer"), default="analyst")
    user_add.add_argument("--tenant-id", default="default")
    user_sub.add_parser("list", help="list users")

    tenant = sub.add_parser("tenant", help="manage tenants")
    tenant_sub = tenant.add_subparsers(dest="tenant_command", required=True)
    tenant_add = tenant_sub.add_parser("add", help="create a tenant")
    tenant_add.add_argument("--name", required=True)
    tenant_add.add_argument("--slug")
    tenant_sub.add_parser("list", help="list tenants")

    sso = sub.add_parser("sso", help="configure OIDC single sign-on")
    sso_sub = sso.add_subparsers(dest="sso_command", required=True)
    sso_config = sso_sub.add_parser("config", help="set OIDC issuer/client settings")
    sso_config.add_argument("--issuer", required=True)
    sso_config.add_argument("--client-id", required=True)
    sso_config.add_argument("--redirect-uri", required=True)
    sso_config.add_argument("--client-secret-env", default="OIDC_CLIENT_SECRET")
    sso_config.add_argument("--scopes", default="openid profile email")
    sso_sub.add_parser("show", help="show SSO config (no secrets)")

    ticket = sub.add_parser("ticket", help="configure and sync external tickets")
    ticket_sub = ticket.add_subparsers(dest="ticket_command", required=True)
    ticket_config = ticket_sub.add_parser("config", help="set ticket provider config")
    ticket_config.add_argument(
        "--provider", choices=("github", "webhook", "jira", "servicenow"), required=True,
    )
    ticket_config.add_argument("--repo", help="GitHub owner/name")
    ticket_config.add_argument("--url", help="generic ticket webhook URL")
    ticket_config.add_argument("--base-url", help="Jira or ServiceNow base URL")
    ticket_config.add_argument("--project-key", help="Jira project key")
    ticket_config.add_argument("--issue-type", default="Bug", help="Jira issue type")
    ticket_config.add_argument("--table", default="incident", help="ServiceNow table")
    ticket_config.add_argument("--email-env", default="JIRA_EMAIL", help="Jira email env var")
    ticket_config.add_argument("--token-env", default="GITHUB_TOKEN")
    ticket_sub.add_parser("list", help="list synced tickets")

    sub.add_parser("list", help="list recent scans")
    show = sub.add_parser("show", help="show one scan as JSON")
    show.add_argument("scan_id")
    compare = sub.add_parser("compare", help="compare findings between two completed scans")
    compare.add_argument("current_scan_id")
    compare.add_argument("baseline_scan_id")
    report = sub.add_parser("report", help="export an HTML or JSON report")
    report.add_argument("scan_id")
    report.add_argument("--format", choices=("html", "json", "sarif"), default="html")
    report.add_argument("--lang", choices=("en", "zh"), default="en", help="HTML report language")
    report.add_argument("--output", type=Path, required=True)
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    storage = Storage(args.db)
    engine = ScanEngine(storage)

    if args.command == "scan":
        try:
            if args.login_flow:
                load_login_flow(args.login_flow)  # validate early; secrets expand at run time
            policy_doc = None
            if args.policy:
                policy_doc = json.loads(Path(args.policy).read_text(encoding="utf-8"))
                load_policy(Path(args.policy))  # validate
            options = ScanOptions(
                custom_headers=parse_header_lines(args.header),
                submit_forms=args.submit_forms,
                openapi_url=args.openapi_url,
                browser_crawl=args.browser_crawl or bool(args.login_flow),
                login_flow_path=str(args.login_flow) if args.login_flow else None,
                graphql=args.graphql,
                graphql_url=args.graphql_url,
                webhook_url=validate_webhook_url(args.webhook),
                fail_on=args.fail_on,
                blind_inject=args.blind_inject,
                api_probe=not args.no_api_probe,
                oast_base_url=validate_oast_base(args.oast_url),
                oast_listen=args.oast_listen,
                secondary_headers=parse_header_lines(args.secondary_header),
                browser_verify=args.browser_verify,
                policy=policy_doc,
            )
        except (ValueError, json.JSONDecodeError, OSError) as exc:
            parser.error(str(exc))
        if args.submit_forms and args.profile != "deep":
            parser.error("--submit-forms requires --profile deep")
        if args.blind_inject and args.profile != "deep":
            parser.error("--blind-inject requires --profile deep")
        if args.oast_listen and args.oast_url:
            parser.error("use either --oast-listen or --oast-url, not both")
        if args.secondary_header and not args.header:
            parser.error("--secondary-header requires primary --header session context")
        result = engine.queue(args.target, args.profile)
        print(f"queued scan {result.scan_id} for {args.target}")
        result = asyncio.run(engine.run(result, allow_private=args.allow_private, options=options))
        print(
            f"{result.status}: {result.stats.pages} page(s), {result.stats.requests} request(s), "
            f"{result.stats.discovered} endpoint(s) "
            f"(http={result.stats.discovered_http}, browser={result.stats.discovered_browser}), "
            f"{len(result.findings)} finding(s), {len(result.errors)} error(s)"
        )
        baseline = result.baseline or {}
        summary = baseline.get("summary") or {}
        if baseline.get("baseline_scan_id"):
            print(
                f"baseline vs {baseline['baseline_scan_id']}: "
                f"new={summary.get('new', 0)} fixed={summary.get('fixed', 0)} "
                f"recurring={summary.get('recurring', 0)}"
            )
        print(f"scan id: {result.scan_id}")
        if result.status == "failed":
            raise SystemExit(2)
        if should_fail(result.findings, args.fail_on):
            print(f"fail-on {args.fail_on}: findings meet CI threshold", file=sys.stderr)
            raise SystemExit(1)
    elif args.command == "serve":
        if args.host not in {"127.0.0.1", "localhost", "::1"} and not args.allow_remote_ui:
            parser.error("binding the console beyond loopback requires --allow-remote-ui")
        if not 1 <= args.port <= 65535:
            parser.error("port must be between 1 and 65535")
        serve(storage, engine, args.host, args.port, enable_scheduler=not args.no_scheduler)
    elif args.command == "schedule":
        if args.schedule_command == "add":
            try:
                item = create_schedule(
                    storage,
                    target=args.target,
                    profile=args.profile,
                    interval_minutes=args.every,
                    allow_private=args.allow_private,
                    openapi_url=args.openapi_url,
                    browser_crawl=args.browser_crawl,
                    graphql=args.graphql,
                    graphql_url=args.graphql_url,
                    webhook_url=args.webhook,
                )
            except ValueError as exc:
                parser.error(str(exc))
            print(f"scheduled {item['id']} every {item['interval_minutes']}m for {item['target']}")
            print(f"next run at {item['next_run_at']}")
        elif args.schedule_command == "list":
            items = storage.list_schedules()
            if not items:
                print("no schedules")
            for item in items:
                state = "on" if item["enabled"] else "off"
                print(
                    f"{item['id']}  {state:<3}  every {item['interval_minutes']:>5}m  "
                    f"next={item['next_run_at']}  {item['target']}"
                )
        elif args.schedule_command == "remove":
            if not storage.delete_schedule(args.schedule_id):
                raise SystemExit(f"schedule not found: {args.schedule_id}")
            print(f"removed schedule {args.schedule_id}")
    elif args.command == "login-template":
        payload = json.dumps(example_login_flow(), ensure_ascii=False, indent=2) + "\n"
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(payload, encoding="utf-8")
            print(f"wrote {args.output}")
        else:
            print(payload, end="")
    elif args.command == "policy-template":
        payload = json.dumps(example_policy(), ensure_ascii=False, indent=2) + "\n"
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(payload, encoding="utf-8")
            print(f"wrote {args.output}")
        else:
            print(payload, end="")
    elif args.command == "login-record":
        try:
            document = asyncio.run(record_login_interactively(
                args.start_url, timeout_seconds=args.timeout, headed=not args.headless,
            ))
        except (ValueError, Exception) as exc:
            parser.error(str(exc))
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"recorded {len(document.get('steps', []))} step(s) → {args.output}")
    elif args.command == "campaign":
        if args.campaign_command == "create":
            targets = [
                line.strip() for line in args.targets_file.read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.strip().startswith("#")
            ]
            try:
                item = create_campaign(storage, CampaignSpec(
                    name=args.name, targets=targets, profile=args.profile, concurrency=args.concurrency,
                    allow_private=args.allow_private, browser_crawl=args.browser_crawl, graphql=args.graphql,
                    webhook_url=args.webhook, blind_inject=args.blind_inject,
                ))
            except ValueError as exc:
                parser.error(str(exc))
            print(f"campaign {item['id']} created with {len(item['targets'])} target(s)")
        elif args.campaign_command == "run":
            result = asyncio.run(run_campaign(storage, engine, args.campaign_id))
            print(f"campaign {result['id']} {result['status']}")
        elif args.campaign_command == "list":
            items = storage.list_campaigns()
            if not items:
                print("no campaigns")
            for item in items:
                done = sum(1 for row in item["targets"] if row["status"] == "completed")
                print(f"{item['id']}  {item['status']:<9}  {done}/{len(item['targets'])}  {item['name']}")
        elif args.campaign_command == "show":
            item = storage.get_campaign(args.campaign_id)
            if not item:
                raise SystemExit(f"campaign not found: {args.campaign_id}")
            print(json.dumps(item, ensure_ascii=False, indent=2))
    elif args.command == "user":
        if args.user_command == "add":
            if storage.user_count() == 0:
                args.role = "admin"
            record, token = create_user_record(args.name, args.role, tenant_id=args.tenant_id)
            record["created_at"] = now_iso()
            storage.create_user(record)
            print(f"created user {record['name']} ({record['role']}) tenant={record['tenant_id']}")
            print(f"api token (store securely, shown once): {token}")
        elif args.user_command == "list":
            users = storage.list_users()
            if not users:
                print("no users (local open mode)")
            for item in users:
                print(f"{item['id']}  {item['role']:<8}  {item.get('tenant_id', 'default'):<12}  {item['name']}")
    elif args.command == "tenant":
        if args.tenant_command == "add":
            item = {
                "id": secrets.token_hex(6),
                "name": args.name[:80],
                "slug": tenant_slug(args.slug or args.name),
                "created_at": now_iso(),
            }
            storage.create_tenant(item)
            print(f"tenant {item['id']}  {item['slug']}  {item['name']}")
        elif args.tenant_command == "list":
            items = storage.list_tenants()
            if not items:
                print("no tenants")
            for item in items:
                print(f"{item['id']}  {item['slug']:<16}  {item['name']}")
    elif args.command == "sso":
        if args.sso_command == "config":
            try:
                config = validate_oidc_config({
                    "issuer": args.issuer,
                    "client_id": args.client_id,
                    "redirect_uri": args.redirect_uri,
                    "client_secret_env": args.client_secret_env,
                    "scopes": args.scopes,
                })
            except ValueError as exc:
                parser.error(str(exc))
            storage.set_sso_config(config)
            print(f"SSO configured for issuer {config['issuer']}")
        elif args.sso_command == "show":
            row = storage.get_sso_config()
            if not row:
                print("SSO not configured")
            else:
                print(json.dumps(row, ensure_ascii=False, indent=2))
    elif args.command == "ticket":
        if args.ticket_command == "config":
            config: dict = {"token_env": args.token_env}
            if args.provider == "github":
                if not args.repo:
                    parser.error("--repo is required for github")
                config["repo"] = args.repo
            elif args.provider == "webhook":
                if not args.url:
                    parser.error("--url is required for webhook")
                config["url"] = args.url
            elif args.provider == "jira":
                if not args.base_url or not args.project_key:
                    parser.error("--base-url and --project-key are required for jira")
                config.update({
                    "base_url": args.base_url, "project_key": args.project_key,
                    "issue_type": args.issue_type, "email_env": args.email_env,
                })
            elif args.provider == "servicenow":
                if not args.base_url:
                    parser.error("--base-url is required for servicenow")
                config.update({"base_url": args.base_url, "table": args.table})
            storage.set_ticket_config(args.provider, validate_ticket_config(args.provider, config))
            print(f"ticket provider set to {args.provider}")
        elif args.ticket_command == "list":
            tickets = storage.list_tickets()
            if not tickets:
                print("no tickets")
            for item in tickets:
                print(f"{item['id']}  {item['status']:<8}  {item['severity']:<7}  {item['title']}")
    elif args.command == "list":
        scans = storage.list_scans()
        if not scans:
            print("no scans")
        for item in scans:
            print(
                f"{item['id']}  {item['status']:<9}  {item['profile']:<8}  "
                f"{item['findings']:>3} finding(s)  {item['target']}"
            )
    elif args.command == "show":
        scan = storage.get_scan(args.scan_id)
        if not scan:
            raise SystemExit(f"scan not found: {args.scan_id}")
        print(json.dumps(scan, ensure_ascii=False, indent=2))
    elif args.command == "compare":
        current = storage.get_scan(args.current_scan_id)
        baseline = storage.get_scan(args.baseline_scan_id)
        if not current:
            raise SystemExit(f"scan not found: {args.current_scan_id}")
        if not baseline:
            raise SystemExit(f"scan not found: {args.baseline_scan_id}")
        comparison = compare_findings(
            current.get("findings_list", []), baseline.get("findings_list", []),
            baseline_scan_id=args.baseline_scan_id,
        )
        print(json.dumps(comparison.to_dict(), ensure_ascii=False, indent=2))
    elif args.command == "report":
        scan = storage.get_scan(args.scan_id)
        if not scan:
            raise SystemExit(f"scan not found: {args.scan_id}")
        write_report(scan, args.output, args.format, lang=getattr(args, "lang", "en"))
        print(f"report saved to {args.output}")


if __name__ == "__main__":
    main()
