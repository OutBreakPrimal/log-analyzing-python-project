import argparse
import json
import re
import sys
from collections import Counter, defaultdict, namedtuple
from datetime import datetime, timedelta
from urllib.parse import unquote

SSHEvent = namedtuple("SSHEvent", "ts ip user kind method raw")
WebEvent = namedtuple("WebEvent", "ts ip method path status ua raw")

SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
COLORS = {"LOW": "\033[36m", "MEDIUM": "\033[33m", "HIGH": "\033[31m",
          "CRITICAL": "\033[1;41m"}
RESET = "\033[0m"


def bump(severity):
    """Raise a severity by one level (used when an attack got a 2xx response)."""
    return SEVERITIES[min(SEVERITIES.index(severity) + 1, len(SEVERITIES) - 1)]


def fmt(ts):
    return ts.strftime("%Y-%m-%d %H:%M:%S")


def finding(sev, category, ip, desc, count, first, last, mitre, evidence):
    return {
        "severity": sev, "category": category, "ip": ip,
        "description": desc, "count": count,
        "first_seen": fmt(first), "last_seen": fmt(last),
        "mitre": mitre, "evidence": [e[:160] for e in evidence[:3]],
    }


def busiest_window(times, window):
    """Sliding window: return (max_count, window_start, window_end)."""
    times = sorted(times)
    best, j = (0, None, None), 0
    for i, t in enumerate(times):
        while t - times[j] > window:
            j += 1
        n = i - j + 1
        if n > best[0]:
            best = (n, times[j], t)
    return best

SYSLOG_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
    r"\s+\S+\s+(?P<proc>[\w\-/.]+)(?:\[\d+\])?:\s+(?P<msg>.*)$")
ISO_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z)?"
    r"\s+\S+\s+(?P<proc>[\w\-/.]+)(?:\[\d+\])?:\s+(?P<msg>.*)$")
IP = r"(?P<ip>[0-9a-fA-F:.]+)"
FAILED_RE = re.compile(r"Failed (?P<method>\S+) for (?:invalid user )?(?P<user>\S+) from " + IP)
ACCEPTED_RE = re.compile(r"Accepted (?P<method>\S+) for (?P<user>\S+) from " + IP)
INVALID_RE = re.compile(r"Invalid user (?P<user>\S*) from " + IP)


def parse_ssh(lines, year):
    events, now = [], datetime.now()
    for raw in lines:
        raw = raw.rstrip("\n")
        m = SYSLOG_RE.match(raw)
        if m:
            try:
                ts = datetime.strptime(
                    f"{year} {m['mon']} {m['day']} {m['time']}", "%Y %b %d %H:%M:%S")
                if ts > now + timedelta(days=1):      
                    ts = ts.replace(year=ts.year - 1)
            except ValueError:
                continue
        else:
            m = ISO_RE.match(raw)
            if not m:
                continue
            ts = datetime.fromisoformat(m["ts"])
        if "sshd" not in m["proc"]:
            continue
        msg = m["msg"]
        if (x := FAILED_RE.search(msg)):
            events.append(SSHEvent(ts, x["ip"], x["user"], "fail", x["method"], raw))
        elif (x := ACCEPTED_RE.search(msg)):
            events.append(SSHEvent(ts, x["ip"], x["user"], "ok", x["method"], raw))
        elif (x := INVALID_RE.search(msg)):
            events.append(SSHEvent(ts, x["ip"], x["user"], "invalid", "-", raw))
    return events


def analyze_ssh(events, a):
    window = timedelta(minutes=a.window)
    by_ip = defaultdict(list)
    for e in events:
        by_ip[e.ip].append(e)
    out = []
    for ip, evs in by_ip.items():
        fails = [e for e in evs if e.kind == "fail"]
        oks = [e for e in evs if e.kind == "ok"]

        if fails:
            n, s, e_ = busiest_window([f.ts for f in fails], window)
            if n >= a.fail_threshold:
                sev = "HIGH" if n >= a.fail_threshold * 5 else "MEDIUM"
                out.append(finding(
                    sev, "SSH brute force", ip,
                    f"{n} failed logins within {a.window} min",
                    len(fails), s, e_, "T1110.001 Password Guessing",
                    [f.raw for f in fails]))

            users = {e.user for e in evs if e.kind in ("fail", "invalid")}
            if len(users) >= a.spray_users:
                out.append(finding(
                    "HIGH", "Password spraying / user enumeration", ip,
                    f"{len(users)} distinct usernames tried "
                    f"(e.g. {', '.join(sorted(users)[:5])})",
                    len(fails), fails[0].ts, fails[-1].ts,
                    "T1110.003 Password Spraying", [f.raw for f in fails]))

        for ok in oks:
            prior = [f for f in fails if ok.ts - window <= f.ts <= ok.ts]
            if len(prior) >= a.fail_threshold:
                out.append(finding(
                    "CRITICAL", "Login after repeated failures", ip,
                    f"Successful login as '{ok.user}' after {len(prior)} failures "
                    f"- possible compromised account",
                    len(prior) + 1, prior[0].ts, ok.ts,
                    "T1078 Valid Accounts", [prior[-1].raw, ok.raw]))
                break

        root_ok = [o for o in oks if o.user == "root"]
        if root_ok:
            out.append(finding(
                "MEDIUM", "Direct root login", ip,
                f"Root logged in via {root_ok[0].method}; prefer sudo + PermitRootLogin no",
                len(root_ok), root_ok[0].ts, root_ok[-1].ts,
                "T1078.003 Local Accounts", [r.raw for r in root_ok]))
    return out

WEB_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>\S+)[^"]*" '
    r'(?P<status>\d{3}) \S+(?: "[^"]*" "(?P<ua>[^"]*)")?')

SIGNATURES = {
    "SQL injection attempt": (re.compile(
        r"(union\s+select|\bor\s+1=1|'\s*or\s*'|sleep\(\d+\)|information_schema|;\s*drop\s)"),
        "T1190 Exploit Public-Facing Application", "HIGH"),
    "Path traversal attempt": (re.compile(
        r"(\.\./|\.\.\\|/etc/passwd|/etc/shadow|boot\.ini)"),
        "T1083 File and Directory Discovery", "HIGH"),
    "XSS attempt": (re.compile(r"(<script|onerror\s*=|javascript:)"),
                    "T1059.007 JavaScript", "MEDIUM"),
    "Command injection attempt": (re.compile(
        r"([;|`]|\$\()\s*(cat|ls|id|whoami|wget|curl|nc|bash|sh)\b|/bin/(ba)?sh"),
        "T1059 Command and Scripting Interpreter", "CRITICAL"),
    "Sensitive path probing": (re.compile(
        r"(\.env\b|\.git/|wp-login\.php|xmlrpc\.php|phpmyadmin|\.aws/credentials"
        r"|id_rsa|\.htpasswd|/server-status)"),
        "T1595.003 Wordlist Scanning", "LOW"),
}
SCANNER_UA = re.compile(
    r"(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wfuzz|hydra|zgrab|nuclei)", re.I)


def parse_web(lines):
    events = []
    for raw in lines:
        m = WEB_RE.match(raw.rstrip("\n"))
        if not m:
            continue
        try:
            ts = datetime.strptime(m["ts"].split()[0], "%d/%b/%Y:%H:%M:%S")
        except ValueError:
            continue
        events.append(WebEvent(ts, m["ip"], m["method"], m["path"],
                               int(m["status"]), m["ua"] or "", raw.rstrip("\n")))
    return events


def analyze_web(events, a):
    window = timedelta(minutes=a.window)
    by_ip = defaultdict(list)
    for e in events:
        by_ip[e.ip].append(e)
    out = []
    for ip, evs in by_ip.items():
        n, s, e_ = busiest_window([x.ts for x in evs], timedelta(seconds=60))
        if n >= a.rate:
            out.append(finding(
                "MEDIUM", "High request rate", ip, f"{n} requests in 60 seconds",
                len(evs), s, e_, "T1499 Endpoint Denial of Service",
                [x.raw for x in evs]))

        errs = [x for x in evs if 400 <= x.status < 500]
        n, s, e_ = busiest_window([x.ts for x in errs], window)
        if n >= a.web_errors:
            out.append(finding(
                "MEDIUM", "Scanning / enumeration", ip,
                f"{n} client errors (4xx) within {a.window} min",
                len(errs), s, e_, "T1595.002 Vulnerability Scanning",
                [x.raw for x in errs]))

        for name, (rx, mitre, base) in SIGNATURES.items():
            hits = [x for x in evs if rx.search(unquote(unquote(x.path)).lower())]
            if not hits:
                continue
            succeeded = [x for x in hits if 200 <= x.status < 300]
            sev, note = (bump(base), f", {len(succeeded)} returned 2xx") if succeeded else (base, "")
            out.append(finding(
                sev, name, ip, f"{len(hits)} matching requests{note}",
                len(hits), hits[0].ts, hits[-1].ts, mitre, [h.raw for h in hits]))

        uas = {x.ua for x in evs if SCANNER_UA.search(x.ua)}
        if uas:
            out.append(finding(
                "MEDIUM", "Known scanner user agent", ip,
                f"User agent(s): {', '.join(sorted(uas))[:80]}",
                len(evs), evs[0].ts, evs[-1].ts, "T1595 Active Scanning",
                [x.raw for x in evs if x.ua in uas]))
    return out

def sort_findings(fs):
    return sorted(fs, key=lambda f: (-SEVERITIES.index(f["severity"]), -f["count"]))


def print_report(fs, stats, color):
    def c(sev):
        return f"{COLORS[sev]}{sev:<8}{RESET}" if color else f"{sev:<8}"

    print("=" * 72)
    print(" LOG ANALYSIS REPORT")
    print("=" * 72)
    for k, v in stats.items():
        print(f" {k:<22}{v}")
    counts = Counter(f["severity"] for f in fs)
    print(" Findings by severity: " + ", ".join(
        f"{s}={counts.get(s, 0)}" for s in reversed(SEVERITIES)))
    print("-" * 72)
    if not fs:
        print(" No suspicious activity detected with current thresholds.")
    for f in fs:
        print(f"\n[{c(f['severity'])}] {f['category']}  ({f['ip']})")
        print(f"   {f['description']}")
        print(f"   {f['first_seen']} -> {f['last_seen']}   events: {f['count']}")
        print(f"   MITRE ATT&CK: {f['mitre']}")
        for ev in f["evidence"][:2]:
            print(f"   > {ev}")
    print()


def write_markdown(path, fs, stats):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("# Log Analysis Report\n\n")
        for k, v in stats.items():
            fh.write(f"- **{k}:** {v}\n")
        fh.write("\n| Severity | Category | Source IP | Details | Events | MITRE |\n")
        fh.write("|---|---|---|---|---|---|\n")
        for f in fs:
            fh.write(f"| {f['severity']} | {f['category']} | `{f['ip']}` | "
                     f"{f['description']} | {f['count']} | {f['mitre']} |\n")
    print(f"Markdown report written to {path}")

def detect_type(lines):
    sample = lines[:200]
    web = sum(1 for l in sample if WEB_RE.match(l))
    ssh = sum(1 for l in sample if "sshd" in l)
    return "web" if web > ssh else "ssh"


def main():
    p = argparse.ArgumentParser(description="Detect suspicious activity in SSH and web logs.")
    p.add_argument("logfiles", nargs="+", help="one or more log files")
    p.add_argument("--type", choices=["auto", "ssh", "web"], default="auto")
    p.add_argument("--year", type=int, default=datetime.now().year,
                   help="year for syslog timestamps that omit it")
    p.add_argument("--window", type=int, default=10, help="detection window in minutes")
    p.add_argument("--fail-threshold", type=int, default=5, help="failed logins to flag")
    p.add_argument("--spray-users", type=int, default=4, help="distinct usernames to flag")
    p.add_argument("--web-errors", type=int, default=15, help="4xx responses to flag")
    p.add_argument("--rate", type=int, default=100, help="requests/minute to flag")
    p.add_argument("--min-severity", choices=SEVERITIES, default="LOW")
    p.add_argument("--json", metavar="FILE", help="write findings as JSON")
    p.add_argument("--markdown", metavar="FILE", help="write a Markdown report")
    a = p.parse_args()

    findings, total_lines, ips = [], 0, set()
    for path in a.logfiles:
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
        except OSError as exc:
            print(f"Cannot read {path}: {exc}", file=sys.stderr)
            return 2
        total_lines += len(lines)
        kind = detect_type(lines) if a.type == "auto" else a.type
        if kind == "ssh":
            ev = parse_ssh(lines, a.year)
            findings += analyze_ssh(ev, a)
        else:
            ev = parse_web(lines)
            findings += analyze_web(ev, a)
        ips |= {e.ip for e in ev}
        print(f"[+] {path}: detected as {kind}, {len(ev)} events parsed", file=sys.stderr)

    floor = SEVERITIES.index(a.min_severity)
    findings = [f for f in sort_findings(findings) if SEVERITIES.index(f["severity"]) >= floor]
    stats = {"Lines read": total_lines, "Unique source IPs": len(ips),
             "Total findings": len(findings)}

    print_report(findings, stats, sys.stdout.isatty())
    if a.json:
        with open(a.json, "w", encoding="utf-8") as fh:
            json.dump(findings, fh, indent=2)
        print(f"JSON written to {a.json}")
    if a.markdown:
        write_markdown(a.markdown, findings, stats)
    return 0


if __name__ == "__main__":
    sys.exit(main())
