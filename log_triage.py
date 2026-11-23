#!/usr/bin/env python3
"""First-pass triage for Apache/Nginx Combined Log Format access logs.

Heuristic output is investigative context, not proof of compromise. Preserve
the source log and validate findings against application and endpoint telemetry.
"""

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote

LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<uri>\S+) (?P<protocol>[^\"]+)" '
    r'(?P<status>\d{3}) (?P<size>\S+) "(?P<referrer>[^\"]*)" "(?P<user_agent>[^\"]*)"$'
)

SIGNATURES = {
    "Path Traversal / LFI": re.compile(r"(\.\./|\.\.\\|%2e%2e|/etc/passwd|win\.ini)", re.I),
    "SQL Injection": re.compile(r"(union\s+select|select.+from|['\"]\s*or\s+['\"]?1['\"]?=|sleep\s*\(|benchmark\s*\()", re.I),
    "Cross-Site Scripting": re.compile(r"(<script|onerror\s*=|onload\s*=|javascript:|alert\s*\()", re.I),
    "SSRF / Metadata Probe": re.compile(r"(169\.254\.169\.254|127\.0\.0\.1|localhost|0\.0\.0\.0|file://|gopher://|dict://)", re.I),
    "Sensitive File Probe": re.compile(r"(/\.env(?:\b|/)|/\.git/config|wp-config\.php|phpinfo\s*\()", re.I),
}
SCANNER_UA = re.compile(r"(sqlmap|nikto|gobuster|ffuf|dirbuster|wpscan|nmap|masscan)", re.I)


def analyze_log_file(filepath: str, burst_threshold: int = 5) -> dict:
    path = Path(filepath)
    events, malformed = [], 0
    with path.open(encoding="utf-8", errors="replace") as log:
        for line_number, raw in enumerate(log, 1):
            line = raw.rstrip("\r\n")
            if not line:
                continue
            match = LOG_PATTERN.match(line)
            if not match:
                malformed += 1
                continue
            item = match.groupdict()
            item.update(line=line_number, status=int(item["status"]))
            # Decode repeatedly only for matching, never more than twice, to
            # surface common double-encoding while retaining the logged URI.
            decoded = unquote(unquote(item["uri"]))
            item["indicators"] = [name for name, pattern in SIGNATURES.items() if pattern.search(decoded)]
            if SCANNER_UA.search(item["user_agent"]):
                item["indicators"].append("Scanner User-Agent")
            events.append(item)

    request_counts = Counter(e["ip"] for e in events)
    not_found_counts = Counter(e["ip"] for e in events if e["status"] == 404)
    technique_by_ip = defaultdict(set)
    for event in events:
        technique_by_ip[event["ip"]].update(event["indicators"])

    alerts, verdicts = [], Counter()
    for event in events:
        indicators = list(event["indicators"])
        is_404_burst = not_found_counts[event["ip"]] >= burst_threshold and event["status"] == 404
        if is_404_burst:
            indicators.append("404 Enumeration Burst")
        if not indicators:
            verdict = "BENIGN"
        elif event["indicators"] and event["status"] in (200, 206):
            # A 2xx response is a lead to investigate, not proof of success.
            verdict = "HIGH_PRIORITY_REVIEW"
        else:
            verdict = "SUSPICIOUS"
        verdicts[verdict] += 1
        if verdict != "BENIGN":
            alerts.append({
                "line": event["line"], "timestamp": event["timestamp"],
                "source_ip": event["ip"], "method": event["method"],
                "uri": event["uri"], "status_code": event["status"],
                "user_agent": event["user_agent"], "indicators": indicators,
                "verdict": verdict,
            })

    offenders = [
        {"source_ip": ip, "total_requests": count,
         "http_404_count": not_found_counts[ip],
         "detected_techniques": sorted(technique_by_ip[ip])}
        for ip, count in request_counts.most_common()
        if technique_by_ip[ip] or not_found_counts[ip] >= burst_threshold
    ]
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "analyzed_file": path.name,
        "total_parsed_requests": len(events),
        "malformed_lines": malformed,
        "verdict_breakdown": dict(verdicts),
        "flagged_source_ips": offenders,
        "alerts": alerts,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Triage Apache/Nginx Combined access logs.")
    parser.add_argument("-f", "--file", default="sample_access.log", help="Input log file")
    parser.add_argument("-o", "--output", default="triage_report.json", help="JSON report path")
    parser.add_argument("--burst-threshold", type=int, default=5, help="404s per source to flag (default: 5)")
    args = parser.parse_args()
    if args.burst_threshold < 1:
        parser.error("--burst-threshold must be at least 1")
    try:
        report = analyze_log_file(args.file, args.burst_threshold)
        Path(args.output).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print("SOC WEB LOG TRIAGE SUMMARY")
    print(f"File: {report['analyzed_file']} | Parsed: {report['total_parsed_requests']} | Malformed: {report['malformed_lines']}")
    print(f"Verdicts: {report['verdict_breakdown']}")
    print(f"Alerts: {len(report['alerts'])} | Report: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

