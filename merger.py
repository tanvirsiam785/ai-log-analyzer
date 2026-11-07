import re
from urllib.parse import unquote_plus
from ledger import SUCCESS_AUTH

SEVERITY = ["Low", "Medium", "High", "Critical"]
TYPES = ["sql_injection", "account_compromise", "brute_force",
         "unauthorized_access", "scanning", "rate_anomaly"]
SQL_RE = re.compile(
    r"union\s+select|select\s.+\sfrom|\bor\b\s*['\"]?\w+['\"]?\s*=\s*['\"]?\w+|--|;\s*drop|"
    r"drop\s+table|information_schema|sleep\s*\(|'\s*or\s",
    re.I,
)
PROTECTED_RE = re.compile(r"/(admin|internal|config|manage|console|backup|debug|\.env|\.git)", re.I)
MIN_DENIED = 5
MAX_BRUTE_PATHS = 5
MIN_PEAK = 30
MIN_LIMITED = 5
MIN_PATHS = 10
MAX_LINES = 30
DEFAULT_ACTION = {
    "brute_force": "Block the IP and force a password reset for the targeted accounts.",
    "account_compromise": "Lock the account, reset credentials and review activity after the login.",
    "sql_injection": "Block the IP, review the endpoint and use parameterized queries.",
    "unauthorized_access": "Block the IP and check access rules on protected paths.",
    "scanning": "Block or rate limit the IP and review exposed paths.",
    "rate_anomaly": "Rate limit or block the IP at the gateway.",
}


def failed_total(entry):
    return max(entry["denied"], entry["fails"])


def is_denied(row):
    if row[1] in (401, 403):
        return True
    return bool(row[3]) and row[3].lower() not in SUCCESS_AUTH


def compromise_text(entry):
    if failed_total(entry) >= 3 and entry["last_success"] > entry["first_fail"] > 0:
        return (f"successful login at line {entry['last_success']} "
                f"after denied logins from line {entry['first_fail']}")
    return ""


def cited_lines(raw, ip, ledger):
    if not isinstance(raw, (list, set)):
        return []
    return sorted({n for n in raw
                   if isinstance(n, int) and n in ledger.rows and ledger.rows[n][0] == ip})


def check(kind, entry, ledger, cited):
    fails = failed_total(entry)
    fallback = entry["ev"][:10]

    if kind == "brute_force":
        if fails < MIN_DENIED:
            return None, f"only {fails} denied logins"
        if len(entry["paths"]) > MAX_BRUTE_PATHS:
            return None, f"{len(entry['paths'])} different paths, not repeated attempts on one target"
        lines = [n for n in cited if is_denied(ledger.rows[n])] or fallback
        return lines, f"{fails} denied logins out of {entry['req']} requests"

    if kind == "account_compromise":
        text = compromise_text(entry)
        if not text:
            return None, "no successful login after denied logins"
        lines = [n for n in cited if is_denied(ledger.rows[n])] or fallback
        return sorted(set(lines + [entry["last_success"]])), f"{fails} denied logins, then {text}"

    if kind == "scanning":
        failed = entry["other4"] + entry["denied"]
        if len(entry["paths"]) < MIN_PATHS or failed * 2 < entry["req"]:
            return None, f"{len(entry['paths'])} paths, {failed}/{entry['req']} failed"
        return cited or fallback, (f"{len(entry['paths'])} distinct paths, "
                                   f"{failed} of {entry['req']} requests failed")

    if kind == "rate_anomaly":
        if entry["peak"] < MIN_PEAK and entry["rl"] < MIN_LIMITED:
            return None, f"peak {entry['peak']} per minute, {entry['rl']} rate-limited"
        return cited or fallback, (f"peak {entry['peak']} requests per minute, "
                                   f"{entry['rl']} rate-limited (429) responses, "
                                   f"up to {entry['win']} requests in the server's window")

    if kind == "sql_injection":
        lines = [n for n in cited
                 if SQL_RE.search(unquote_plus(ledger.rows[n][2] + " " + ledger.rows[n][4]))]
        if not lines:
            return None, "no cited line contains SQL syntax"
        return lines, f"{len(lines)} requests with SQL syntax"

    if kind == "unauthorized_access":
        lines = []
        for n in cited:
            row = ledger.rows[n]
            if "login" in row[2].lower():
                continue
            if row[1] in (401, 403) or PROTECTED_RE.search(row[2]):
                lines.append(n)
        if not lines:
            return None, "no cited line hits a protected path"
        return lines, f"{len(lines)} requests to protected paths or denied"

    return None, "unsupported type"


def verify(finding, ledger):
    if not isinstance(finding, dict):
        return None, "not an object"
    ip = finding.get("ip")
    kind = finding.get("type")
    entry = ledger.ips.get(ip) if isinstance(ip, str) else None
    if entry is None:
        return None, "ip not in log"
    if kind not in TYPES:
        return None, "unsupported type"
    severity = finding.get("severity")
    if severity not in SEVERITY:
        severity = "Medium"
    cited = cited_lines(finding.get("lines"), ip, ledger)
    lines, info = check(kind, entry, ledger, cited)
    if lines is None:
        return None, info
    return {
        "type": kind,
        "severity": severity,
        "ip": ip,
        "lines": sorted(set(lines)),
        "evidence": info,
        "model_reason": str(finding.get("reason", ""))[:120],
        "action": str(finding.get("action", ""))[:100],
        "chunks": [],
    }, ""


def evaluate(group, entry, ledger):
    cited = cited_lines(group["lines"], group["ip"], ledger)
    claimed = [t for t in group["types"] if t in TYPES]
    results = []
    reasons = []
    for kind in claimed:
        lines, info = check(kind, entry, ledger, cited)
        if lines is None:
            reasons.append(f"{kind}: {info}")
        else:
            results.append((kind, lines, info, False))
    if not results:
        for kind in TYPES:
            if kind in claimed:
                continue
            lines, info = check(kind, entry, ledger, cited)
            if lines is not None:
                results.append((kind, lines, info, True))
    return results, "; ".join(reasons)


def build_report(claims, ledger):
    groups = {}
    for claim in claims:
        if not isinstance(claim, dict):
            continue
        ip = claim.get("ip")
        if not isinstance(ip, str):
            continue
        group = groups.setdefault(ip, {
            "ip": ip, "types": [], "lines": set(), "chunks": set(),
            "severity": None, "actions": {}, "reasons": {}, "reports": 0,
        })
        kind = claim.get("type")
        if isinstance(kind, str):
            if kind not in group["types"]:
                group["types"].append(kind)
            if claim.get("action"):
                group["actions"][kind] = str(claim["action"])[:100]
            if claim.get("reason"):
                group["reasons"][kind] = str(claim["reason"])[:120]
        raw = claim.get("lines")
        if isinstance(raw, list):
            group["lines"].update(n for n in raw if isinstance(n, int))
        chunks = claim.get("chunks")
        if isinstance(chunks, list):
            group["chunks"].update(n for n in chunks if isinstance(n, int))
        sev = claim.get("severity")
        if sev in SEVERITY:
            if group["severity"] is None or SEVERITY.index(sev) > SEVERITY.index(group["severity"]):
                group["severity"] = sev
        group["reports"] += 1

    report = []
    dropped = []
    for ip, group in groups.items():
        entry = ledger.ips.get(ip)
        if entry is None:
            dropped.append({"ip": ip, "claimed": group["types"], "why": "ip not in log"})
            continue
        results, why = evaluate(group, entry, ledger)
        if not results:
            dropped.append({"ip": ip, "claimed": group["types"],
                            "why": why or "no attack type supported by the ledger"})
            continue
        for kind, lines, evidence, changed in results:
            if changed:
                reason = (f"model flagged this IP as {', '.join(group['types'])}; "
                          f"the ledger supports {kind}")
                action = DEFAULT_ACTION[kind]
            else:
                reason = group["reasons"].get(kind, "")
                action = group["actions"].get(kind) or DEFAULT_ACTION[kind]
            item = {
                "type": kind,
                "severity": group["severity"] or "Medium",
                "ip": ip,
                "lines": sorted(set(lines))[:MAX_LINES],
                "evidence": evidence,
                "model_reason": reason,
                "action": action,
                "chunks": sorted(group["chunks"]),
                "reports": group["reports"],
                "reclassified": changed,
            }
            link = compromise_text(entry)
            if link and kind != "account_compromise":
                item["link"] = link
                item["severity"] = "Critical"
            report.append(item)

    report.sort(key=lambda r: (-SEVERITY.index(r["severity"]), r["ip"], r["type"]))
    return report, dropped