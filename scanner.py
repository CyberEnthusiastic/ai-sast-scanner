"""
AI-Powered SAST (Static Application Security Testing) Scanner
Scans source code for security vulnerabilities using pattern matching,
AST analysis, and ML-based risk scoring.

Author: Adithya Vasamsetti (CyberEnthusiastic)
"""
import os
import re
import ast
import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass, asdict, field
from typing import List, Dict, Optional


# -------------------------------------------------------------
# Vulnerability pattern database
# Each pattern maps to CWE + OWASP Top 10 + severity + remediation
# -------------------------------------------------------------
VULN_PATTERNS = [
    {
        "id": "SQLI-001",
        "name": "SQL Injection (string concatenation)",
        "pattern": r"(?:execute|executemany|query|cursor\.execute)\s*\(\s*[f\"'].*?\{|(?:execute|query)\s*\(\s*['\"].*?['\"]?\s*\+",
        "severity": "CRITICAL",
        "cwe": "CWE-89",
        "owasp": "A03:2021 - Injection",
        "confidence": 0.95,
        "remediation": "Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
        "example_fix": "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
    },
    {
        "id": "CMDI-001",
        "name": "Command Injection (os.system / subprocess shell=True)",
        "pattern": r"(?:os\.system|os\.popen|subprocess\.(?:call|run|Popen)\s*\([^)]*shell\s*=\s*True)",
        "severity": "CRITICAL",
        "cwe": "CWE-78",
        "owasp": "A03:2021 - Injection",
        "confidence": 0.92,
        "remediation": "Use subprocess with a list of args and shell=False. Validate/escape any user input.",
        "example_fix": "subprocess.run(['ls', user_dir], shell=False, check=True)",
    },
    {
        "id": "DESER-001",
        "name": "Insecure Deserialization (pickle)",
        "pattern": r"pickle\.loads?\s*\(|cPickle\.loads?\s*\(|yaml\.load\s*\((?!.*Loader\s*=\s*yaml\.SafeLoader)",
        "severity": "CRITICAL",
        "cwe": "CWE-502",
        "owasp": "A08:2021 - Software and Data Integrity Failures",
        "confidence": 0.90,
        "remediation": "Use JSON or yaml.safe_load(). Never unpickle data from untrusted sources.",
        "example_fix": "data = json.loads(payload)",
    },
    {
        "id": "SECRET-001",
        "name": "Hardcoded Secret / API Key",
        "pattern": r"(?i)(?:api[_-]?key|secret|password|token|aws_secret|private[_-]?key)\s*=\s*['\"][A-Za-z0-9/+_\-]{16,}['\"]",
        "severity": "CRITICAL",
        "cwe": "CWE-798",
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "confidence": 0.88,
        "remediation": "Store secrets in environment variables, Vault, or AWS Secrets Manager.",
        "example_fix": "API_KEY = os.environ['API_KEY']",
    },
    {
        "id": "EVAL-001",
        "name": "Dangerous eval() / exec() usage",
        "pattern": r"\b(?:eval|exec)\s*\(",
        "severity": "CRITICAL",
        "cwe": "CWE-95",
        "owasp": "A03:2021 - Injection",
        "confidence": 0.93,
        "remediation": "Avoid eval/exec. Use ast.literal_eval() for safe parsing of literals.",
        "example_fix": "import ast; data = ast.literal_eval(safe_input)",
    },
    {
        "id": "XSS-001",
        "name": "Cross-Site Scripting (innerHTML with untrusted data)",
        "pattern": r"\.innerHTML\s*=\s*(?!['\"])|document\.write\s*\(",
        "severity": "HIGH",
        "cwe": "CWE-79",
        "owasp": "A03:2021 - Injection",
        "confidence": 0.85,
        "remediation": "Use textContent, or sanitize with DOMPurify before assigning to innerHTML.",
        "example_fix": "element.textContent = userInput;",
    },
    {
        "id": "PATH-001",
        "name": "Path Traversal (open with unsanitized path)",
        "pattern": r"open\s*\(\s*(?:['\"].*?\+|f['\"].*?\{|request\.(?:args|form|params))",
        "severity": "HIGH",
        "cwe": "CWE-22",
        "owasp": "A01:2021 - Broken Access Control",
        "confidence": 0.80,
        "remediation": "Validate with os.path.realpath() and check it stays inside an allowlist directory.",
        "example_fix": "safe = os.path.realpath(os.path.join(BASE, name))\nassert safe.startswith(BASE)",
    },
    {
        "id": "CRYPTO-001",
        "name": "Weak Cryptographic Hash (MD5 / SHA1)",
        "pattern": r"hashlib\.(?:md5|sha1)\s*\(",
        "severity": "HIGH",
        "cwe": "CWE-327",
        "owasp": "A02:2021 - Cryptographic Failures",
        "confidence": 0.98,
        "remediation": "Use hashlib.sha256() or bcrypt/argon2 for password hashing.",
        "example_fix": "h = hashlib.sha256(data).hexdigest()",
    },
    {
        "id": "SSRF-001",
        "name": "Server-Side Request Forgery (requests with user URL)",
        "pattern": r"requests\.(?:get|post|put|delete)\s*\(\s*(?:request\.|f['\"])",
        "severity": "HIGH",
        "cwe": "CWE-918",
        "owasp": "A10:2021 - Server-Side Request Forgery",
        "confidence": 0.82,
        "remediation": "Validate URLs against an allowlist of domains. Block internal IPs (169.254.*, 10.*, 192.168.*).",
        "example_fix": "from urllib.parse import urlparse\nassert urlparse(url).hostname in ALLOWED_HOSTS",
    },
    {
        "id": "DEBUG-001",
        "name": "Debug mode enabled in production",
        "pattern": r"(?:DEBUG|debug)\s*=\s*True|app\.run\s*\([^)]*debug\s*=\s*True",
        "severity": "MEDIUM",
        "cwe": "CWE-489",
        "owasp": "A05:2021 - Security Misconfiguration",
        "confidence": 0.90,
        "remediation": "Disable debug mode in production. Read from environment: debug=os.getenv('DEBUG')=='1'",
        "example_fix": "app.run(debug=False, host='0.0.0.0')",
    },
]


@dataclass
class Finding:
    id: str
    name: str
    severity: str
    cwe: str
    owasp: str
    file: str
    line: int
    code_snippet: str
    confidence: float
    remediation: str
    example_fix: str
    risk_score: float = 0.0
    fingerprint: str = ""


class MLRiskScorer:
    """
    Lightweight ML-style risk scorer.
    Combines pattern confidence + contextual signals (user input proximity,
    dangerous sinks, framework hints) into a 0-100 risk score.
    """

    DANGER_KEYWORDS = ["request.", "input(", "sys.argv", "getenv", "params",
                       "form[", "args[", "body.", "query."]
    SAFE_KEYWORDS = ["sanitize", "escape", "validate", "allowlist", "whitelist",
                     "parameterized", "prepared"]

    def score(self, finding: Finding, context_lines: List[str]) -> float:
        base = finding.confidence * 60  # 0-60
        context_blob = " ".join(context_lines).lower()

        danger_hits = sum(1 for k in self.DANGER_KEYWORDS if k in context_blob)
        safe_hits = sum(1 for k in self.SAFE_KEYWORDS if k in context_blob)

        base += min(danger_hits * 8, 30)
        base -= min(safe_hits * 10, 25)

        if finding.severity == "CRITICAL":
            base += 10
        elif finding.severity == "HIGH":
            base += 5

        return max(0.0, min(100.0, round(base, 2)))


class SASTScanner:
    SUPPORTED_EXT = {".py", ".js", ".ts", ".jsx", ".tsx", ".html", ".php", ".java", ".rb"}

    def __init__(self):
        self.scorer = MLRiskScorer()
        self.findings: List[Finding] = []
        self.files_scanned = 0
        self.lines_scanned = 0

    def scan(self, target: str) -> List[Finding]:
        target_path = Path(target)
        if target_path.is_file():
            self._scan_file(target_path)
        elif target_path.is_dir():
            for f in target_path.rglob("*"):
                if f.is_file() and f.suffix in self.SUPPORTED_EXT:
                    self._scan_file(f)
        return self.findings

    def _scan_file(self, path: Path):
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception:
            return
        self.files_scanned += 1
        self.lines_scanned += len(lines)

        for i, line in enumerate(lines):
            for pat in VULN_PATTERNS:
                if re.search(pat["pattern"], line):
                    context_start = max(0, i - 3)
                    context_end = min(len(lines), i + 4)
                    context = lines[context_start:context_end]

                    finding = Finding(
                        id=pat["id"],
                        name=pat["name"],
                        severity=pat["severity"],
                        cwe=pat["cwe"],
                        owasp=pat["owasp"],
                        file=str(path),
                        line=i + 1,
                        code_snippet=line.strip()[:200],
                        confidence=pat["confidence"],
                        remediation=pat["remediation"],
                        example_fix=pat["example_fix"],
                    )
                    finding.risk_score = self.scorer.score(finding, context)
                    finding.fingerprint = hashlib.sha1(
                        f"{path}:{i}:{pat['id']}".encode()
                    ).hexdigest()[:12]
                    self.findings.append(finding)

    def summary(self) -> Dict:
        by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in self.findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        return {
            "files_scanned": self.files_scanned,
            "lines_scanned": self.lines_scanned,
            "total_findings": len(self.findings),
            "by_severity": by_sev,
            "scanned_at": datetime.now(tz=timezone.utc).isoformat(),
        }


def main():
    from license_guard import verify_license, print_banner
    verify_license()
    print_banner("AI SAST Scanner")
    import argparse
    parser = argparse.ArgumentParser(
        description="AI-Powered SAST Code Scanner — finds vulns with ML risk scoring"
    )
    parser.add_argument("target", help="File or directory to scan")
    parser.add_argument("-o", "--output", default="reports/sast_report.json",
                        help="JSON report output path")
    parser.add_argument("--html", default="reports/sast_report.html",
                        help="HTML report output path")
    args = parser.parse_args()

    print("=" * 60)
    print("  AI-Powered SAST Scanner v1.0")
    print("=" * 60)
    print(f"[*] Target: {args.target}")

    scanner = SASTScanner()
    findings = scanner.scan(args.target)
    summary = scanner.summary()

    print(f"[*] Files scanned : {summary['files_scanned']}")
    print(f"[*] Lines scanned : {summary['lines_scanned']}")
    print(f"[*] Total findings: {summary['total_findings']}")
    print(f"[*] Breakdown     : {summary['by_severity']}")
    print()

    for f in sorted(findings, key=lambda x: -x.risk_score):
        color = "\033[91m" if f.severity == "CRITICAL" else "\033[93m"
        reset = "\033[0m"
        print(f"{color}[{f.severity}]{reset} {f.name}")
        print(f"   {f.file}:{f.line} (risk={f.risk_score}, {f.cwe})")
        print(f"   > {f.code_snippet}")
        print()

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w") as fp:
        json.dump({
            "summary": summary,
            "findings": [asdict(f) for f in findings]
        }, fp, indent=2)
    print(f"[+] JSON report: {args.output}")

    from report_generator import generate_html
    generate_html(summary, findings, args.html)
    print(f"[+] HTML report: {args.html}")


if __name__ == "__main__":
    main()
