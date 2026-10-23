# Cloud IAM Entitlement Audit

A lightweight static audit project for detecting common cloud configuration risks in Terraform/HCL and JSON files, including public storage settings, broad IAM permissions, and potential hard-coded credentials.

> **Safety and scope:** This project scans local files only. It does not connect to cloud accounts, modify infrastructure, or guarantee that a repository is secure. Findings are review signals and may include false positives.

## Files

- `cloud_iam_entitlement_audit.py` — Python static scanner.
- `requirements.txt` — no third-party Python dependencies are required.
- `Requirements.pdf` — runtime and optional tooling requirements.
- `Project_Report.pdf` — project overview, methodology, rules, sample usage, limitations, and recommendations.
- `logo.png` — supplied project/institution logo used in the report.

## Requirements

- Python 3.10+
- Windows, macOS, or Linux
- Read access to the repository being scanned
- Optional: [Checkov](https://www.checkov.io/) and Terraform CLI for additional IaC checks

## Run the Python scanner

```bash
python cloud_iam_entitlement_audit.py ./terraform
```

Write findings to JSON:

```bash
python cloud_iam_entitlement_audit.py ./terraform --json audit-findings.json
```

Choose the severity threshold for a non-zero exit code:

```bash
python cloud_iam_entitlement_audit.py ./terraform --fail-on CRITICAL
```

Supported thresholds: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `NEVER`.

## Optional Checkov and Terraform checks

Install Checkov:

```bash
python -m pip install checkov
checkov -d ./terraform --framework terraform
```

If Terraform is installed and the directory is a valid Terraform working directory:

```bash
terraform fmt -check -recursive
terraform init -backend=false
terraform validate
```

Run these commands in a test or review environment and follow your organization's policies.

## Detection rules

| Rule | Severity | What it flags |
|---|---|---|
| CIA001 | High | Storage ACLs such as `public-read` / `public-read-write` |
| CIA002 | High | Selected storage public-access protections explicitly set to `false` |
| CIA003 | High | `publicly_accessible = true` |
| CIA004 | High | IAM actions set to wildcard `*` |
| CIA005 | High | IAM resources set to wildcard `*` |
| CIA006 | High | Possible AWS access-key identifiers |
| CIA007 | Critical | Private-key header material |
| CIA008 | High review signal | IAM policy `Allow` statements |
| CIA009 | Medium | Empty versioning blocks |
| CIA010 | High | Possible hard-coded secret values |

Some rules are intentionally heuristic. For example, an `Allow` statement is not inherently insecure; its scope and conditions must be reviewed.

## Suggested workflow

1. Run the scanner against the infrastructure-as-code repository.
2. Review each finding and confirm the surrounding resource/policy context.
3. Run Checkov and Terraform validation where appropriate.
4. Prioritize exposed credentials and public data access.
5. Replace hard-coded secrets with a managed secret store or workload identity.
6. Narrow IAM permissions to least privilege and document exceptions.
7. Re-run checks after changes and retain the findings as an audit artifact.

## Exit codes

- `0` — no findings at or above the configured `--fail-on` threshold.
- `1` — at least one finding at or above the configured threshold.
- `2` — invalid input path.

A zero exit code means only that configured patterns did not match at the selected threshold; it is not proof of security.

## License

Add the license required by your institution or project owner before public redistribution.
