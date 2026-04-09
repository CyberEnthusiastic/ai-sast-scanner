# ⚡ AI SAST Scanner

> **Production-grade static application security testing — zero dependencies, ML risk scoring, CWE/OWASP mapped.**
> A free, self-hosted alternative to SonarQube, Snyk, Checkmarx, and Veracode for teams that want SAST without the enterprise price tag.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![GitHub Actions](https://img.shields.io/badge/CI-GitHub%20Actions-2088FF?logo=github-actions&logoColor=white)](./.github/workflows/sast.yml)
[![OWASP](https://img.shields.io/badge/OWASP-Top%2010%20mapped-A14241)](https://owasp.org/Top10/)

---

## What it does (in one screenshot of terminal output)

```
============================================================
  AI-Powered SAST Scanner v1.0
============================================================
[*] Target: samples/
[*] Files scanned : 2
[*] Lines scanned : 102
[*] Total findings: 16
[*] Breakdown     : {'CRITICAL': 10, 'HIGH': 5, 'MEDIUM': 1, 'LOW': 0}

[CRITICAL] SQL Injection (string concatenation)
   samples/vulnerable_app.py:23 (risk=98.0, CWE-89)
   > query = f"SELECT * FROM users WHERE username = '{username}'"

[CRITICAL] Command Injection (os.system / subprocess shell=True)
   samples/vulnerable_app.py:32 (risk=95.0, CWE-78)
   > os.system("ls " + cmd)
```

And opens this interactive dark-mode HTML report with per-finding drill-down:
- Severity chip · Rule ID · Risk score · Code snippet · CWE · OWASP · Remediation · Suggested fix

---

## Why you want this

| | **AI SAST Scanner** | SonarQube CE | Snyk Open Source | Semgrep OSS |
|---|---|---|---|---|
| **Price** | Free (MIT) | Free (limited) | Free (limited scans) | Free |
| **Runtime deps** | **None** — pure stdlib | Java + Postgres | Node | Python |
| **Install time** | `git clone && python scanner.py` | Multi-step | CLI + account | `pip install semgrep` |
| **Self-hosted** | Yes, no account needed | Yes | No (cloud) | Yes |
| **CWE + OWASP mapping** | Per rule | Per rule | Per rule | Per rule |
| **Interactive HTML report** | Bundled | Requires server | No | No |
| **ML-style risk scoring** | Yes (0–100) | No | No | No |
| **Extend with Python regex** | 5 lines | Plugin SDK | No | YAML DSL |

---

## 60-second quickstart (Windows, macOS, Linux)

```bash
# 1. Clone
git clone https://github.com/CyberEnthusiastic/ai-sast-scanner.git
cd ai-sast-scanner

# 2. Run it (zero install — pure Python 3.8+ stdlib)
python scanner.py samples/

# 3. Open the HTML report
start reports/sast_report.html      # Windows
open  reports/sast_report.html      # macOS
xdg-open reports/sast_report.html   # Linux
```

### Alternative: one-command installer

```bash
# Linux / macOS / WSL / Git Bash
./install.sh

# Windows PowerShell
.\install.ps1
```

The installer verifies your Python version, creates a `.venv/`, installs
dependencies (if any), runs the self-test, and prints next steps.

### Alternative: Docker

```bash
docker build -t ai-sast-scanner .
docker run --rm -v "$PWD/target:/app/target" ai-sast-scanner scanner.py target/
```

---

## Open in VS Code (2 clicks)

```bash
code .
```

VS Code will automatically prompt you to install the recommended extensions
(Python, Pylance, Ruff, GitLens). Then:

1. Press **F5** to launch the scanner in the debugger
2. Or hit **Ctrl+Shift+B** to run the default task (scan samples)
3. Or open the Command Palette → "Tasks: Run Task" → pick from the list

The repo ships with:
- `.vscode/launch.json` — 3 debug profiles (scan samples, scan current file, prompt for path)
- `.vscode/tasks.json` — scan, open report, install deps
- `.vscode/extensions.json` — recommended extensions
- `.vscode/settings.json` — formatter, rulers, spell-check words

**Total time from clone to first scan in VS Code: under 2 minutes.**

---

## What it detects (10 rule classes)

| ID | Class | Severity | CWE | Confidence |
|----|-------|----------|-----|------------|
| SQLI-001 | SQL Injection (string concat / f-strings) | CRITICAL | CWE-89 | 0.95 |
| CMDI-001 | Command Injection (`os.system`, `shell=True`) | CRITICAL | CWE-78 | 0.92 |
| DESER-001 | Insecure Deserialization (pickle, yaml.load) | CRITICAL | CWE-502 | 0.90 |
| SECRET-001 | Hardcoded Secrets / API Keys | CRITICAL | CWE-798 | 0.88 |
| EVAL-001 | `eval()` / `exec()` on user input | CRITICAL | CWE-95 | 0.93 |
| XSS-001 | innerHTML / document.write XSS | HIGH | CWE-79 | 0.85 |
| PATH-001 | Path Traversal | HIGH | CWE-22 | 0.80 |
| CRYPTO-001 | Weak Hash (MD5 / SHA1) | HIGH | CWE-327 | 0.98 |
| SSRF-001 | Server-Side Request Forgery | HIGH | CWE-918 | 0.82 |
| DEBUG-001 | Debug mode enabled in production | MEDIUM | CWE-489 | 0.90 |

See `scanner.py` → `VULN_PATTERNS` for the full rule definitions and add your
own in ~5 lines of Python.

---

## How the ML risk scorer works

`MLRiskScorer` blends signals to produce a 0–100 score per finding:

- **Pattern confidence** (base 60) — each rule ships with a hand-calibrated confidence 0.80–0.98
- **Danger proximity** (+8 per hit, capped +30) — `request.`, `input(`, `sys.argv`, `getenv`, `params`, `form[`, `args[` within ±3 lines
- **Sanitization proximity** (−10 per hit, capped −25) — `sanitize`, `escape`, `validate`, `allowlist`, `parameterized`, `prepared` within ±3 lines
- **Severity bonus** — +10 for CRITICAL, +5 for HIGH

A raw `hashlib.md5()` call in a crypto module scores ~75 (pure pattern), but
`hashlib.md5(request.args['pw'])` jumps to ~95 because the `request.` sink
is within 3 lines. This is the "AI" in the name — not an LLM, but a tiny
contextual classifier that beats pure regex by a wide margin.

---

## Scan your own code

```bash
# Scan an entire project
python scanner.py /path/to/your/project

# Scan a single file
python scanner.py src/auth/login.py

# Custom output paths
python scanner.py . -o reports/prod.json --html reports/prod.html
```

The scanner recursively picks up `*.py`, `*.js`, `*.ts`, `*.jsx`, `*.tsx`,
`*.html`, `*.php`, `*.java`, `*.rb` files. Extend `SUPPORTED_EXT` in
`scanner.py` to add more.

---

## CI/CD integration (fail the build on CRITICAL findings)

Already wired in `.github/workflows/sast.yml`. The workflow:
1. Runs the scanner against `samples/` on every push/PR
2. Uploads the JSON + HTML reports as artifacts
3. (Optional) Fails the build if any CRITICAL finding exists

To fail builds automatically, add this step to the workflow:

```yaml
- name: Fail on CRITICAL
  run: |
    python -c "
    import json, sys
    r = json.load(open('reports/sast_report.json'))
    if r['summary']['by_severity']['CRITICAL'] > 0:
        print('CRITICAL findings detected, failing build')
        sys.exit(1)
    "
```

---

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

That's it. No YAML, no plugins, no server reboot.

---

## Project layout

```
ai-sast-scanner/
├── scanner.py            # main scanner + 10 rules + ML scorer
├── report_generator.py   # dark-mode HTML report
├── samples/              # intentionally vulnerable code for demos
│   ├── vulnerable_app.py
│   └── vulnerable_frontend.js
├── reports/              # output (gitignored)
├── .github/workflows/
│   └── sast.yml          # CI that runs scanner on every PR
├── .vscode/              # launch.json, tasks.json, extensions.json
├── Dockerfile            # containerized runs
├── install.sh            # one-command installer (Linux/Mac/WSL)
├── install.ps1           # one-command installer (Windows)
├── requirements.txt      # empty — pure stdlib
├── README.md             # this file
├── LICENSE               # MIT
├── NOTICE                # attribution
├── SECURITY.md           # vulnerability disclosure policy
└── CONTRIBUTING.md       # how to add rules / send PRs
```

---

## Roadmap

- [ ] AST-based taint tracking (beyond regex)
- [ ] SARIF output for GitHub Code Scanning
- [ ] Fine-tuned CodeBERT classifier for low-confidence findings
- [ ] Git blame integration — assign findings to authors
- [ ] Semgrep rule import adapter

## License

MIT. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).

## Security

Responsible disclosure policy: see [SECURITY.md](./SECURITY.md).

## Contributing

PRs welcome! See [CONTRIBUTING.md](./CONTRIBUTING.md) for the quick path
from fork to merged PR.

---

Built by **[Adithya Vasamsetti (CyberEnthusiastic)](https://github.com/CyberEnthusiastic)** as part of the [AI Security Projects](https://github.com/CyberEnthusiastic?tab=repositories) suite — a set of zero-dependency, commercial-grade security tools for engineers and teams who want serious security without serious SaaS bills.
