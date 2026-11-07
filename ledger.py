MAX_PATHS = 200
MAX_USERS = 50
MAX_EVIDENCE = 12
KEEP_HEAD = 8
SUCCESS_AUTH = {"success", "succeeded", "ok", "granted", "passed", "allowed"}
SKIP_BLOB = {"time", "app", "host", "service", "level", "client_ip", "request_id",
             "method", "user_agent", "status", "response_bytes", "duration_ms"}


class Ledger:
    def __init__(self):
        self.ips = {}
        self.rows = {}
        self.last_line = 0

    def add_chunk(self, chunk):
        for line_no, rec in chunk["records"]:
            if line_no <= self.last_line:
                continue
            self.last_line = line_no
            if not rec:
                continue
            ip = rec.get("client_ip")
            if not ip:
                continue
            entry = self.ips.get(ip)
            if entry is None:
                entry = {
                    "req": 0, "ok": 0, "denied": 0, "other4": 0, "err5": 0,
                    "bad": 0, "paths": set(), "users": set(), "auth": {},
                    "first": "", "last": "", "ev": [],
                    "minute": "", "min_count": 0, "peak": 0, "flags": [],
                    "fails": 0, "first_fail": 0, "last_success": 0,
                    "rl": 0, "win": 0,
                }
                self.ips[ip] = entry
            self.update(entry, line_no, rec)

    def update(self, entry, line_no, rec):
        entry["req"] += 1
        status = rec.get("status")
        if isinstance(status, int):
            if status in (401, 403):
                entry["denied"] += 1
                if not entry["first_fail"]:
                    entry["first_fail"] = line_no
            elif 200 <= status < 400:
                entry["ok"] += 1
            elif 400 <= status < 500:
                entry["other4"] += 1
                if status == 429:
                    entry["rl"] += 1
            elif status >= 500:
                entry["err5"] += 1

        window = rec.get("requests_in_window")
        if isinstance(window, int):
            entry["win"] = max(entry["win"], window)

        auth = rec.get("auth_result")
        if auth:
            entry["auth"][auth] = entry["auth"].get(auth, 0) + 1
            if str(auth).lower() in SUCCESS_AUTH:
                entry["last_success"] = line_no
            else:
                entry["fails"] += 1
                if not entry["first_fail"]:
                    entry["first_fail"] = line_no

        path = rec.get("path")
        if path and len(entry["paths"]) < MAX_PATHS:
            entry["paths"].add(path)

        user = rec.get("username")
        if user and len(entry["users"]) < MAX_USERS:
            entry["users"].add(user)

        stamp = str(rec.get("time", ""))
        if stamp:
            if not entry["first"]:
                entry["first"] = stamp
            entry["last"] = stamp
            minute = stamp[:16]
            if minute == entry["minute"]:
                entry["min_count"] += 1
            else:
                entry["minute"] = minute
                entry["min_count"] = 1
            entry["peak"] = max(entry["peak"], entry["min_count"])

        flagged_line = (isinstance(status, int) and status >= 400) or bool(auth)
        if flagged_line:
            entry["bad"] += 1
            entry["ev"].append(line_no)
            if len(entry["ev"]) > MAX_EVIDENCE:
                del entry["ev"][KEEP_HEAD]

        blob = " ".join(str(v) for k, v in rec.items()
                        if k not in SKIP_BLOB and not isinstance(v, (dict, list)))
        self.rows[line_no] = (
            rec.get("client_ip"),
            status if isinstance(status, int) else 0,
            str(path or "")[:120],
            str(auth or ""),
            blob[:300],
        )

    def flag(self, ip, kind):
        entry = self.ips.get(ip)
        if entry is not None and kind and kind not in entry["flags"]:
            entry["flags"].append(kind)

    def describe(self, ip, entry):
        parts = [
            f"{ip}: req={entry['req']}",
            f"ok={entry['ok']}",
            f"denied={entry['denied']}",
            f"other4xx={entry['other4']}",
            f"5xx={entry['err5']}",
            f"peak/min={entry['peak']}",
            f"paths={len(entry['paths'])}",
            f"users={len(entry['users'])}",
        ]
        if entry["rl"]:
            parts.append(f"rl429={entry['rl']}")
        if entry["auth"]:
            parts.append("auth=" + ",".join(f"{k}:{v}" for k, v in entry["auth"].items()))
        first = entry["first"][5:16].replace("T", " ")
        last = entry["last"][11:16]
        parts.append(f"span={first}..{last}")
        if entry["ev"]:
            parts.append("lines=" + ",".join(map(str, entry["ev"])))
        if entry["flags"]:
            parts.append("flagged=" + ",".join(entry["flags"]))
        return " ".join(parts)

    def render(self, chunk, budget, count):
        ips = []
        for _, rec in chunk["records"]:
            if rec and rec.get("client_ip") and rec["client_ip"] not in ips:
                ips.append(rec["client_ip"])

        ips.sort(key=lambda ip: (-self.ips[ip]["bad"], -self.ips[ip]["req"]))

        lines = []
        used = 0
        for ip in ips:
            entry = self.ips[ip]
            if entry["req"] < 2 and entry["bad"] == 0:
                continue
            text = self.describe(ip, entry)
            cost = count(text) + 1
            if used + cost > budget:
                break
            lines.append(text)
            used += cost
        return "\n".join(lines) if lines else "none"