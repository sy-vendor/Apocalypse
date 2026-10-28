from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass


SQL_ERROR = re.compile(
    r"(?is)(?:"
    r"you have an error in your sql syntax|"
    r"warning: mysql_|"
    r"unclosed quotation mark after the character string|"
    r"quoted string not properly terminated|"
    r"pg::syntaxerror|"
    r"syntax error at or near|"
    r"sqlite3?\.(?:operational)?error|"
    r"ora-\d{5}|"
    r"microsoft ole db provider for sql server|"
    r"odbc sql server driver|"
    r"sqlstate\["
    r")"
)

COMMAND_ERROR = re.compile(
    r"(?is)(?:"
    r"/bin/(?:ba)?sh: .*(?:not found|No such file)|"
    r"sh: .*: (?:command )?not found|"
    r"'.+' is not recognized as an internal or external command|"
    r"cmd\.exe|"
    r"powershell:|"
    r"cannot run program "
    r")"
)

INJECTION_PARAM_HINT = re.compile(
    r"(?i)^(?:id|ids|q|query|search|sort|order|filter|category|user|uid|item|page|offset|limit|name)$"
)

# Bounded delays only — never long sleep chains or stacked heavy payloads.
TIME_DELAY_SECONDS = 2.0
TIME_CONFIRM_THRESHOLD = 1.5


@dataclass(frozen=True, slots=True)
class InjectionHit:
    kind: str
    pattern: str
    payload: str
    confirmed: bool


@dataclass(frozen=True, slots=True)
class ResponseFingerprint:
    status_code: int
    length: int
    digest: str

    def differs(self, other: "ResponseFingerprint") -> bool:
        return (
            self.status_code != other.status_code
            or abs(self.length - other.length) >= 24
            or self.digest != other.digest
        )


def looks_injection_parameter(name: str) -> bool:
    return bool(INJECTION_PARAM_HINT.match(name))


def detect_sql_error(body: str) -> str | None:
    match = SQL_ERROR.search(body or "")
    return match.group(0)[:120] if match else None


def detect_command_error(body: str) -> str | None:
    match = COMMAND_ERROR.search(body or "")
    return match.group(0)[:120] if match else None


def sql_probe_payloads(marker: str) -> tuple[str, str]:
    return f"{marker}'", f'{marker}"'


def command_probe_payloads(marker: str) -> tuple[str, str]:
    return f"{marker};apocalypse", f"{marker}|apocalypse"


def boolean_payloads(marker: str) -> tuple[str, str]:
    """True/false canaries for boolean-based blind SQLi heuristics."""
    true_payload = f"1' OR '{marker}'='{marker}"
    false_payload = f"1' OR '{marker}'='{marker}x"
    return true_payload, false_payload


def boolean_chain_payloads(marker: str) -> tuple[str, str, str]:
    """True → false → true sequence for exploit-chain consistency checks."""
    true_payload, false_payload = boolean_payloads(marker)
    true_again = f"1' OR '{marker}'='{marker}' OR '1'='1"
    return true_payload, false_payload, true_again


def time_payloads() -> tuple[str, ...]:
    """Short, single-delay probes for authorized deep scans only."""
    return (
        "1' AND SLEEP(2)-- ",
        "1';SELECT CASE WHEN (1=1) THEN pg_sleep(2) ELSE pg_sleep(0) END-- ",
    )


def time_control_payload() -> str:
    """No-delay control used to compare against a bounded sleep canary."""
    return "1' AND 1=1-- "


def fingerprint_response(status_code: int, body: str) -> ResponseFingerprint:
    digest = hashlib.sha256((body or "").encode("utf-8", errors="replace")).hexdigest()[:16]
    return ResponseFingerprint(status_code=status_code, length=len(body or ""), digest=digest)


def fp_dict(fp: ResponseFingerprint) -> dict[str, int | str]:
    return {"status_code": fp.status_code, "length": fp.length, "digest": fp.digest}


def score_boolean_chain(
    true_fp: ResponseFingerprint,
    false_fp: ResponseFingerprint,
    true_again_fp: ResponseFingerprint,
) -> dict[str, object]:
    """Require true≠false and true≈true_again before treating the chain as verified."""
    differential = true_fp.differs(false_fp)
    stable = not true_fp.differs(true_again_fp)
    return {
        "differential": differential,
        "stable_true": stable,
        "chain_verified": differential and stable,
        "phases": {"true": fp_dict(true_fp), "false": fp_dict(false_fp), "true_again": fp_dict(true_again_fp)},
    }


def score_time_chain(control_elapsed: float, delayed_elapsed: float, confirm_elapsed: float) -> dict[str, object]:
    delayed = delayed_elapsed >= TIME_CONFIRM_THRESHOLD
    control_fast = control_elapsed < TIME_CONFIRM_THRESHOLD
    confirmed = delayed and confirm_elapsed >= TIME_CONFIRM_THRESHOLD and control_fast
    return {
        "control_elapsed": round(control_elapsed, 3),
        "delayed_elapsed": round(delayed_elapsed, 3),
        "confirm_elapsed": round(confirm_elapsed, 3),
        "chain_verified": confirmed,
        "delay_seconds": TIME_DELAY_SECONDS,
    }
