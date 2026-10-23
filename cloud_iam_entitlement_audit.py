#!/usr/bin/env python3
"""
Cloud IAM Entitlement Audit
Static audit of Terraform/HCL, tfvars, and JSON files for common cloud exposure risks.

This tool is a local static checker. It does not connect to cloud accounts or change
resources. Findings require human review; this is not a substitute for Checkov,
provider-native security tools, or a formal penetration test.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

SUPPORTED_SUFFIXES = {".tf", ".tfvars", ".hcl", ".json"}
SKIP_DIRS = {".git", ".terraform", "node_modules", "venv", ".venv", "__pycache__"}

@dataclass
class Finding:
    severity: str
    rule_id: str
    file: str
    line: int
    message: str
    evidence: str
    recommendation: str

RULES = [
    {
        "id": "CIA001", "severity": "HIGH",
        "pattern": re.compile(r'(?i)^\s*acl\s*=\s*["\']public-read(?:-write)?["\']'),
        "message": "Storage ACL appears to allow public access.",
        "recommendation": "Remove public ACLs; use least-privilege IAM and block public access unless explicitly approved."
    },
    {
        "id": "CIA002", "severity": "HIGH",
        "pattern": re.compile(r'(?i)^\s*(?:block_public_acls|block_public_policy|ignore_public_acls|restrict_public_buckets)\s*=\s*false\b'),
        "message": "A storage public-access protection setting is disabled.",
        "recommendation": "Enable all applicable public-access-block settings and document any approved exception."
    },
    {
        "id": "CIA003", "severity": "HIGH",
        "pattern": re.compile(r'(?i)^\s*publicly_accessible\s*=\s*true\b'),
        "message": "A cloud database/resource is marked publicly accessible.",
        "recommendation": "Set publicly_accessible to false where possible and restrict network access to approved sources."
    },
    {
        "id": "CIA004", "severity": "HIGH",
        "pattern": re.compile(r'(?i)^\s*actions?\s*=\s*\[\s*["\']\*["\']\s*\]'),
        "message": "IAM policy grants wildcard action permissions.",
        "recommendation": "Replace wildcard actions with the smallest set of required actions."
    },
    {
        "id": "CIA005", "severity": "HIGH",
        "pattern": re.compile(r'(?i)^\s*resources?\s*=\s*\[\s*["\']\*["\']\s*\]'),
        "message": "IAM policy scope includes every resource.",
        "recommendation": "Scope permissions to specific resource ARNs/IDs and review the business justification."
    },
    {
        "id": "CIA006", "severity": "HIGH",
        "pattern": re.compile(r'(?i)(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16})'),
        "message": "Possible hard-coded cloud access key identifier.",
        "recommendation": "Revoke/rotate exposed credentials immediately and use a secret manager or workload identity."
    },
    {
        "id": "CIA007", "severity": "CRITICAL",
        "pattern": re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----'),
        "message": "Private-key material appears in a configuration file.",
        "recommendation": "Remove the key from source history, rotate/revoke it, and store secrets in an approved secret manager."
    },
    {
        "id": "CIA008", "severity": "HIGH",
        "pattern": re.compile(r'(?i)^\s*effect\s*=\s*["\']Allow["\']'),
        "message": "IAM policy contains an Allow statement; inspect its actions, resources, and conditions.",
        "recommendation": "Validate that the Allow statement is narrowly scoped and protected by suitable conditions. This is a review signal, not automatically a vulnerability."
    },
    {
        "id": "CIA009", "severity": "MEDIUM",
        "pattern": re.compile(r'(?i)^\s*versioning\s*\{\s*\}\s*$'),
        "message": "Empty versioning block detected; verify storage recovery/versioning configuration.",
        "recommendation": "Enable and verify object versioning where recovery and audit requirements call for it."
    },
]

SECRET_PATTERNS = [
    re.compile(r'(?i)^\s*(?:password|client_secret|secret_access_key|api_key|token)\s*=\s*["\'][^${][^"\']{7,}["\']\s*$')
]

def iter_files(root: Path) -> Iterable[Path]:
    if root.is_file():
        if root.suffix.lower() in SUPPORTED_SUFFIXES:
            yield root
        return
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in SUPPORTED_SUFFIXES:
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        yield path

def scan_file(path: Path, base: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return findings
    try:
        display_path = str(path.relative_to(base))
    except ValueError:
        display_path = str(path)

    for number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("//"):
            continue
        for rule in RULES:
            if rule["pattern"].search(line):
                findings.append(Finding(
                    severity=rule["severity"], rule_id=rule["id"], file=display_path,
                    line=number, message=rule["message"], evidence=stripped[:240],
                    recommendation=rule["recommendation"]
                ))
        for pattern in SECRET_PATTERNS:
            if pattern.search(line) and not re.search(r'(?i)(var\.|data\.|lookup\(|\$\{|\$\()', line):
                findings.append(Finding(
                    severity="HIGH", rule_id="CIA010", file=display_path, line=number,
                    message="Possible hard-coded secret value.",
                    evidence=re.sub(r'(["\']).*?\\1', r'\\1[REDACTED]\\1', stripped)[:240],
                    recommendation="Replace hard-coded secrets with variables backed by a secret manager; rotate any real exposed secret."
                ))
    return findings

def main() -> int:
    parser = argparse.ArgumentParser(description="Static audit for common Terraform/cloud entitlement risks.")
    parser.add_argument("path", nargs="?", default=".", help="File or directory to scan (default: current directory)")
    parser.add_argument("--json", dest="json_out", help="Write findings to a JSON file")
    parser.add_argument("--fail-on", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEVER"], default="HIGH",
                        help="Exit non-zero when a finding at or above this severity exists (default: HIGH)")
    args = parser.parse_args()

    root = Path(args.path).resolve()
    if not root.exists():
        print(f"Error: path does not exist: {root}", file=sys.stderr)
        return 2
    base = root if root.is_dir() else root.parent
    findings = []
    files = sorted(iter_files(root))
    for file in files:
        findings.extend(scan_file(file, base))

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda f: (order.get(f.severity, 9), f.file, f.line))
    print(f"Cloud IAM Entitlement Audit — scanned {len(files)} file(s); found {len(findings)} finding(s).")
    if not findings:
        print("No configured patterns matched. This does not prove the infrastructure is secure.")
    for item in findings:
        print(f"[{item.severity}] {item.rule_id} {item.file}:{item.line} — {item.message}")
        print(f"  Evidence: {item.evidence}")
        print(f"  Recommendation: {item.recommendation}")

    if args.json_out:
        target = Path(args.json_out)
        target.write_text(json.dumps([asdict(f) for f in findings], indent=2), encoding="utf-8")
        print(f"JSON report written to: {target}")

    thresholds = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NEVER": 99}
    threshold = thresholds[args.fail_on]
    should_fail = any(order.get(f.severity, 9) <= threshold for f in findings)
    return 1 if should_fail else 0

if __name__ == "__main__":
    raise SystemExit(main())
