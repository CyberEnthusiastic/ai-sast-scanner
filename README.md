# AI-Powered SAST Scanner

A lightweight Static Application Security Testing (SAST) tool that scans source code for vulnerabilities using pattern matching + AST analysis + an ML-style contextual risk scorer. Produces both JSON and a self-contained dark-mode HTML report.

**Zero external dependencies** — runs on Python 3.8+ stdlib only.

## Features

- 10 vulnerability classes out of the box (extensible rule engine)
- CWE + OWASP Top 10 tagging for every finding
- Contextual ML risk scorer (0–100) that boosts score near user-input sinks and lowers it near sanitization keywords
- Unique fingerprint per finding (for deduplication / suppression)
- Dark-mode interactive HTML report with collapsible findings
- JSON output for CI/CD pipelines

## Vulnerabilities detected

| ID | Class | Severity | CWE |
|----|-------|----------|-----|
| SQLI-001 | SQL Injection (string concatenation / f-strings) | CRITICAL | CWE-89 |
| CMDI-001 | Command Injection (`os.system`, `shell=True`) | CRITICAL | CWE-78 |
| DESER-001 | Insecure Deserialization (pickle, yaml.load) | CRITICAL | CWE-502 |
| SECRET-001 | Hardcoded Secrets / API Keys | CRITICAL | CWE-798 |
| EVAL-001 | `eval()` / `exec()` on user input | CRITICAL | CWE-95 |
| XSS-001 | innerHTML / document.write XSS | HIGH | CWE-79 |
| PATH-001 | Path Traversal | HIGH | CWE-22 |
| CRYPTO-001 | Weak Hash (MD5 / SHA1) | HIGH | CWE-327 |
| SSRF-001 | Server-Side Request Forgery | HIGH | CWE-918 |
| DEBUG-001 | Debug mode enabled in production | MEDIUM | CWE-489 |

## Quickstart

```bash
# 1. Clone
git clone https://github.com/CyberEnthusiastic/ai-sast-scanner.git
cd ai-sast-scanner

# 2. Scan the bundled vulnerable samples
python scanner.py samples/

# 3. Open the HTML report
# Windows
start reports/sast_report.html
# macOS
open reports/sast_report.html
# Linux
xdg-open reports/sast_report.html
```

## Sample output

```
============================================================
  AI-Powered SAST Scanner v1.0
============================================================
[*] Target: samples/
[*] Files scanned : 2
[*] Lines scanned : 82
[*] Total findings: 17
[*] Breakdown     : {'CRITICAL': 11, 'HIGH': 5, 'MEDIUM': 1, 'LOW': 0}

[CRITICAL] SQL Injection (string concatenation)
   samples/vulnerable_app.py:23 (risk=98.0, CWE-89)
   > query = f"SELECT * FROM users WHERE username = '{username}'"
...
```

## Scan your own code

```bash
python scanner.py /path/to/your/project
python scanner.py app.py -o reports/my.json --html reports/my.html
```

## How the ML risk scorer works

`MLRiskScorer` computes a 0–100 score per finding by combining:

- **Pattern confidence** (0.80–0.98 depending on rule) → base score (0–60)
- **Danger proximity**: `+8` for every `request.`, `input(`, `sys.argv`, `getenv`, `params`, `form[`, `args[` within ±3 lines (capped at +30)
- **Sanitization proximity**: `−10` for every `sanitize`, `escape`, `validate`, `allowlist`, `parameterized`, `prepared` within ±3 lines (capped at −25)
- **Severity bonus**: `+10` for CRITICAL, `+5` for HIGH

Result: A raw `hashlib.md5()` call in a crypto module scores ~75 (pure pattern), but `hashlib.md5(request.args['pw'])` jumps to ~95 because of the `request.` sink proximity.

## Extending the rule engine

Add a new rule to `VULN_PATTERNS` in `scanner.py`:

```python
{
    "id": "XXE-001",
    "name": "XML External Entity (XXE)",
    "pattern": r"etree\.parse\s*\(|xml\.sax\.parse\s*\(",
    "severity": "HIGH",
    "cwe": "CWE-611",
    "owasp": "A05:2021 - Security Misconfiguration",
    "confidence": 0.85,
    "remediation": "Use defusedxml or disable external entities.",
    "example_fix": "from defusedxml import ElementTree as ET",
},
```

## Running in CI/CD (GitHub Actions example)

```yaml
- name: SAST scan
  run: |
    python scanner.py .
    # fail build if any critical findings
    python -c "import json; r=json.load(open('reports/sast_report.json')); exit(1 if r['summary']['by_severity']['CRITICAL']>0 else 0)"
```

## Roadmap

- [ ] AST-based taint tracking (beyond regex)
- [ ] SARIF output for GitHub Code Scanning
- [ ] Fine-tuned CodeBERT classifier for low-confidence findings
- [ ] Git blame integration — assign findings to authors
- [ ] Semgrep rule import adapter

## License

MIT

---

Built by [CyberEnthusiastic](https://github.com/CyberEnthusiastic) · Part of the AI Security Projects series
