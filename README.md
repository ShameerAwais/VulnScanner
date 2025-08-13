# Web Application Vulnerability Scanner

A concise, non-intrusive web application vulnerability assessment tool. It performs passive reconnaissance and targeted checks, then generates structured reports in multiple formats.

## Features

- Target handling: URL/domain validation, HTTP and HTTPS support
- Discovery: crawling, hidden path detection, form extraction
- Vulnerability indicators: headers, cookies, OWASP Top 10 signals
- Input vectors: reflected XSS, SQLi indicators, command injection, path traversal, file upload, CSRF
- Technology and directory enumeration
- Authentication support with session and CSRF handling
- Smart crawling and false-positive reduction
- DVWA-focused checks for demonstration
- Reporting: TXT, HTML, Markdown, JSON

## Installation

Prerequisites: Python 3.7+, pip

```bash
pip install -r requirements.txt
```

## Usage

Interactive mode (recommended):
```bash
python run_scanner.py
```

Command line:
```bash
python run_scanner.py <target_url> [options]
```

Direct scanner:
```bash
python scanner.py <target_url>
```

Options:
```text
--depth INT       Maximum crawl depth (default: 3)
--timeout INT     Request timeout in seconds (default: 30)
--output FORMAT   txt | html | md | json (default: txt)
--username USER   Username for authentication
--password PASS   Password for authentication
```

Examples:
```bash
# Basic
python scanner.py https://example.com

# Authenticated
python run_scanner.py https://example.com --username admin --password secret

# Deep scan with HTML report
python scanner.py https://example.com --depth 5 --output html
```

## Output

- Text (.txt): human-readable; includes findings and evidence
- HTML (.html): shareable, styled report
- Markdown (.md): documentation-friendly
- JSON (.json): machine-readable for integrations

## Scan Flow

1) Validate target and resolve domain
2) Optional authentication with CSRF/session handling
3) Crawl, discover links and forms, enumerate hidden paths
4) Assess headers, cookies, inputs, tech stack, directory listings
5) Generate report with risk levels, evidence, and recommendations

## Risk Levels (examples)

- Critical: SQL/command injection, critical misconfigurations
- High: reflected XSS, file upload, missing critical headers, path traversal
- Medium: missing headers, open directories, CSRF/SSRF indicators
- Low: minor information disclosure/config issues
- Info: technology stack, hidden fields, general observations

## Ethics and Legal

- For authorized security testing only
- Obtain permission before scanning
- Respect robots.txt and rate limits
- Comply with laws and organizational policies

## Configuration and Structure

Key files:
```text
scanner.py           # Scanner implementation
run_scanner.py       # Interactive CLI
config.py            # Payloads and settings
report_generator.py  # Report creation
reports/             # Generated reports
```

## Troubleshooting

- Connection: verify URL, connectivity, timeouts, proxy/firewall
- Auth: confirm credentials, CSRF handling, session state
- Imports: install dependencies, correct Python version, activate venv
- Permissions: ensure write access to `reports/`

## License

Provided for educational and authorized testing purposes. Users are responsible for legal compliance.
