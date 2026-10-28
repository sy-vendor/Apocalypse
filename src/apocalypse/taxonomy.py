"""CWE / OWASP Top 10 mappings for Apocalypse rule IDs."""

from __future__ import annotations

from typing import Any

from .models import Finding


# OWASP Top 10 2021 identifiers.
RULE_TAXONOMY: dict[str, dict[str, str]] = {
    "header.missing.hsts": {"cwe": "CWE-319", "owasp": "A02:2021", "cwe_name": "Cleartext Transmission of Sensitive Information"},
    "header.missing.csp": {"cwe": "CWE-693", "owasp": "A05:2021", "cwe_name": "Protection Mechanism Failure"},
    "header.missing.xcto": {"cwe": "CWE-16", "owasp": "A05:2021", "cwe_name": "Configuration"},
    "header.missing.referrer": {"cwe": "CWE-200", "owasp": "A01:2021", "cwe_name": "Exposure of Sensitive Information"},
    "header.missing.permissions": {"cwe": "CWE-16", "owasp": "A05:2021", "cwe_name": "Configuration"},
    "banner.server-version": {"cwe": "CWE-200", "owasp": "A05:2021", "cwe_name": "Exposure of Sensitive Information"},
    "cors.wildcard": {"cwe": "CWE-942", "owasp": "A05:2021", "cwe_name": "Permissive Cross-domain Policy"},
    "cors.origin-reflection": {"cwe": "CWE-942", "owasp": "A05:2021", "cwe_name": "Permissive Cross-domain Policy"},
    "cookie.missing-flags": {"cwe": "CWE-614", "owasp": "A05:2021", "cwe_name": "Sensitive Cookie Without Secure Flag"},
    "secret.private-key": {"cwe": "CWE-321", "owasp": "A02:2021", "cwe_name": "Use of Hard-coded Cryptographic Key"},
    "secret.aws-access-key": {"cwe": "CWE-798", "owasp": "A07:2021", "cwe_name": "Use of Hard-coded Credentials"},
    "secret.jwt": {"cwe": "CWE-522", "owasp": "A07:2021", "cwe_name": "Insufficiently Protected Credentials"},
    "error.stack-trace": {"cwe": "CWE-209", "owasp": "A04:2021", "cwe_name": "Generation of Error Message Containing Sensitive Information"},
    "directory.listing": {"cwe": "CWE-548", "owasp": "A01:2021", "cwe_name": "Exposure of Information Through Directory Listing"},
    "transport.mixed-content": {"cwe": "CWE-319", "owasp": "A02:2021", "cwe_name": "Cleartext Transmission of Sensitive Information"},
    "form.password-over-http": {"cwe": "CWE-319", "owasp": "A02:2021", "cwe_name": "Cleartext Transmission of Sensitive Information"},
    "form.csrf-token-heuristic": {"cwe": "CWE-352", "owasp": "A01:2021", "cwe_name": "Cross-Site Request Forgery"},
    "xss.reflected-unencoded": {"cwe": "CWE-79", "owasp": "A03:2021", "cwe_name": "Cross-site Scripting"},
    "input.reflection": {"cwe": "CWE-79", "owasp": "A03:2021", "cwe_name": "Cross-site Scripting"},
    "redirect.external": {"cwe": "CWE-601", "owasp": "A01:2021", "cwe_name": "URL Redirection to Untrusted Site"},
    "sqli.error-based": {"cwe": "CWE-89", "owasp": "A03:2021", "cwe_name": "SQL Injection"},
    "sqli.boolean-blind": {"cwe": "CWE-89", "owasp": "A03:2021", "cwe_name": "SQL Injection"},
    "sqli.time-based": {"cwe": "CWE-89", "owasp": "A03:2021", "cwe_name": "SQL Injection"},
    "cmdi.error-based": {"cwe": "CWE-78", "owasp": "A03:2021", "cwe_name": "OS Command Injection"},
    "lfi.path-traversal": {"cwe": "CWE-22", "owasp": "A01:2021", "cwe_name": "Path Traversal"},
    "ssti.template-injection": {"cwe": "CWE-94", "owasp": "A03:2021", "cwe_name": "Code Injection"},
    "ssrf.oast-callback": {"cwe": "CWE-918", "owasp": "A10:2021", "cwe_name": "Server-Side Request Forgery"},
    "graphql.introspection-enabled": {"cwe": "CWE-200", "owasp": "A05:2021", "cwe_name": "Exposure of Sensitive Information"},
    "authz.idor-differential": {"cwe": "CWE-639", "owasp": "A01:2021", "cwe_name": "Authorization Bypass Through User-Controlled Key"},
    "auth.login-replay-failed": {"cwe": "CWE-287", "owasp": "A07:2021", "cwe_name": "Improper Authentication"},
    "auth.session-expired": {"cwe": "CWE-613", "owasp": "A07:2021", "cwe_name": "Insufficient Session Expiration"},
}


def taxonomy_for(rule_id: str) -> dict[str, str]:
    return dict(RULE_TAXONOMY.get(rule_id) or {})


def annotate_finding(finding: Finding | dict[str, Any]) -> dict[str, Any]:
    if isinstance(finding, Finding):
        data = finding.to_dict()
    else:
        data = dict(finding)
    tax = taxonomy_for(str(data.get("rule_id") or ""))
    if tax:
        evidence = dict(data.get("evidence") or {})
        evidence.setdefault("cwe", tax.get("cwe"))
        evidence.setdefault("owasp", tax.get("owasp"))
        evidence.setdefault("cwe_name", tax.get("cwe_name"))
        data["evidence"] = evidence
        data["cwe"] = tax.get("cwe")
        data["owasp"] = tax.get("owasp")
    return data


SEVERITY_TO_SARIF = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}
