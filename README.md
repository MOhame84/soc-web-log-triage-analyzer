# SOC Web Log Triage Analyzer

A dependency-free Python CLI that parses Apache/Nginx Combined Log Format and highlights common web attack indicators for analyst review.

## Features

- Detects common traversal, SQL injection, XSS, SSRF/metadata, and sensitive-file indicators.
- Decodes the request URI for matching while preserving the original logged URI in results.
- Flags scanner user agents and per-source 404 enumeration bursts.
- Writes a JSON report with parsed and malformed line counts, verdicts, alerts, and source summaries.
- Uses `HIGH_PRIORITY_REVIEW` for indicator-bearing 2xx responses. A successful HTTP status is a triage lead, not proof of exploitation.

## Requirements and usage

Python 3.9+; no third-party packages are required.

```bash
python3 log_triage.py --file sample_access.log --output triage_report.json
python3 log_triage.py -f /path/to/access.log -o report.json --burst-threshold 8
```

Input is expected to use the Apache/Nginx Combined Log Format. Unmatched non-empty lines are counted as malformed instead of silently disappearing. The default 404 burst threshold is five requests per source in the analyzed file; this simple file-wide heuristic does not measure a time window.

## Output and interpretation

`triage_report.json` is an example output generated from the included synthetic sample. Tune signatures and thresholds for your environment. Treat findings as leads: correlate with application events, response sizes, reverse-proxy/WAF logs, and endpoint telemetry before escalating as confirmed compromise.

## Limitations

Regex signatures can miss obfuscation and create false positives. The tool does not reconstruct sessions, establish exploit success, resolve trusted proxy chains, or parse every custom log format. Keep an original copy of evidence and avoid using this tool as an automated blocking decision.

## Safety

Use only on logs you are authorized to access. The sample data is synthetic and uses documentation/private-range addresses.

