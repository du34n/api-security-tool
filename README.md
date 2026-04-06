# api-sec-tool

A command-line API security scanner that automatically tests endpoints for common vulnerabilities and generates a detailed HTML report with risk scoring.

## What it does

Scans REST API endpoints against 26 attack categories and produces an interactive HTML report showing risk scores, vulnerability details, and remediation recommendations for each endpoint.

**Attack coverage:**

- Auth bypass, BOLA/IDOR, BFLA, JWT none algorithm
- SQL injection, NoSQL injection, command injection, XSS, path traversal
- XXE, SSRF, open redirect, LDAP injection, CRLF injection
- CORS misconfiguration, missing security headers, content-type confusion
- Mass assignment, excessive data exposure, sensitive data exposure
- HTTP method override, verb tampering, parameter pollution
- Improper asset management, API version exposure
- Rate limit bypass, business logic flaws, GraphQL introspection

## Installation

**Requirements:** Go 1.19+

```
git clone https://github.com/du34n/api-security-tool
cd api-security-tool
go build -o api-sec-tool .
```

## Usage

**Scan from a Swagger / OpenAPI spec URL:**

```
./api-sec-tool -s https://api.example.com/swagger.json
```

**Scan from a config file:**

```
./api-sec-tool -c config.json
```

**Specify output directory:**

```
./api-sec-tool -s https://api.example.com/openapi.json -o ./reports
```

After the scan completes, open `report.html` in a browser to view the full interactive report.

## Config file format

Create a `config.json` to define targets manually:

```json
{
  "base_url": "https://api.example.com",
  "auth_token": "your-token-here",
  "timeout_seconds": 10,
  "concurrency": 5,
  "global_headers": {
    "Content-Type": "application/json"
  },
  "endpoints": [
    { "method": "GET",    "url": "/users" },
    { "method": "GET",    "url": "/users/1" },
    { "method": "POST",   "url": "/users" },
    { "method": "DELETE", "url": "/users/1" }
  ]
}
```

See `config.example.json` for a full example.

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-s` | | Swagger / OpenAPI spec URL (auto-discovers all endpoints) |
| `-c` | `config.json` | Path to config file |
| `-o` | `.` | Output directory for reports |

## Output

Two files are generated after each scan:

- `report.html` — interactive report with per-endpoint risk scores, finding details, evidence, and recommendations
- `report.json` — machine-readable version of the full report

## Risk scoring

Each endpoint receives a score from 0 to 100 based on:

- Severity of findings (critical/high/medium/low)
- Statistical anomalies in response time and size (Z-score)
- HTTP status codes (500 errors, unauthenticated DELETE success, etc.)

| Score | Level |
|-------|-------|
| 75-100 | Critical |
| 50-74 | High |
| 25-49 | Medium |
| 0-24 | Low |

## Legal

Only use this tool against systems you own or have explicit written permission to test.
