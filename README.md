# 🌐 Cloud Compliance Automation Framework (CCAF)

![Status](https://img.shields.io/badge/status-active-success.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![Build](https://img.shields.io/badge/build-passing-brightgreen.svg)
![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)
![IaC](https://img.shields.io/badge/IaC-Terraform%20%7C%20Pulumi-blueviolet)
![Clouds](https://img.shields.io/badge/clouds-AWS%20%7C%20Azure%20%7C%20GCP-ff69b4)

---

## 🚀 Enterprise Overview
**Cloud Compliance Automation Framework (CCAF)** is an enterprise-grade, modular platform for **continuous compliance-as-code**, automated evidence collection, and **policy-driven remediation** across multi-cloud estates (AWS, Azure, GCP). CCAF translates regulatory and security requirements into **repeatable, auditable pipelines** so organizations can operationalize risk reduction and maintain **audit readiness at scale**.

**Core Objectives**
- Real-time **compliance posture** with proactive drift detection.
- **Audit-ready evidence** mapped to frameworks (ISO/IEC 27001, NIST CSF, CIS, PCI-DSS, GDPR).
- **Shift-left** checks in DevSecOps pipelines with Gates/Approvals.
- Enterprise-grade governance: **RBAC**, secure secret handling, logging, immutable audit trails.

---

## 🧭 Table of Contents
- Executive Summary & Audience
- Key Capabilities
- Architecture & Components
- Repository Structure
- Deployment Guide (copy-paste ready)
- CI/CD Integration
- Hardening & Operational Guidance
- Audit Reporting & Evidence
- Observability & Metrics
- Compliance Coverage & Mapping
- Security, Disclosure & NDA
- Testing & Quality Gates
- Roadmap & Governance
- License
- References
- Contact

---

## ✨ Key Capabilities (Executive Summary)
- **Policy-as-Code Engine** — Pluggable, framework-aligned rule packs with custom extensions.
- **Automated Continuous Scanning** — Inventory + config drift for IAM, storage, networking, KMS, logging, encryption.
- **Remediation-as-Code** — Idempotent, gated playbooks with approvals and rollback.
- **Evidence & Reporting** — Structured JSON/CSV + PDF bundles mapped to controls and owners.
- **Dashboards** — Prometheus/Grafana posture, trends, SLO/SLA, MTTR.
- **IaC Integration** — Terraform / CloudFormation / ARM / Pulumi + pre-commit checks.
- **Pipeline Hooks** — Native GitHub Actions, GitLab CI, Jenkins for PR/push controls.
- **Operational Runbooks** — Incident, forensics, and remediation playbooks.
- **Security-First** — Zero-trust defaults, least privilege, secret vaults, immutable evidence.

---

## 👥 Audience
- Security & Cloud Architects
- DevSecOps and Platform Engineers
- Compliance, Audit & Risk Teams
- Managed Security Service Providers (MSSPs)

---

## 🧱 Architecture & Components (High Level)

- **CLI / API Layer**: Operator and pipeline entrypoints (scan, policy check, report, remediate).
- **Policy Engine**: Rule evaluation, framework mappings, exception handling, waivers.
- **Connectors**: Cloud SDK clients (AWS/Azure/GCP), pagination, throttling, retries.
- **Evidence Store**: Structured snapshots, diffs, and artifacts with integrity metadata.
- **Remediation Engine**: Change sets with dry-run, approvals, rollback, and audit logs.
- **Telemetry**: Exporters for metrics (Prometheus) and logs (SIEM).
- **Dashboards**: Grafana boards for posture, trend, and throughput.
- **Secrets & Config**: Centralized via Vault/Secrets Manager; no plaintext secrets.

---

## 📂 Repository Structure
    cloud-compliance-framework/
    ├─ build/              # Build automation artifacts
    ├─ config/             # Policy sets, templates, env configs
    │  ├─ environments/    # Local/dev/prod configs (YAML/JSON)
    │  └─ policies/        # Compliance policies & mappings
    ├─ docs/               # Documentation, runbooks, compliance matrix
    ├─ infrastructure/     # Terraform, CloudFormation, Ansible templates
    ├─ logs/               # Log outputs of scans and framework runs
    ├─ monitoring/         # Prometheus + Grafana dashboards
    ├─ reports/            # Auto-generated compliance reports
    ├─ scripts/            # Setup, automation, orchestration scripts
    ├─ src/                # Core framework (policy engine, remediation, utils)
    ├─ tests/              # Unit, integration & end-to-end tests
    └─ requirements.txt    # Python dependencies

---

## 🏗️ Deployment Guide (Copy-Paste Safe)

> Run initial deployments in **non-production** or isolated accounts. Follow corporate change control.

### 1) Prerequisites
- Python 3.11+ (virtualenv/venv)
- Non-root IAM / Service Principal with **scoped** permissions
- Terraform ≥ 1.4 (Ansible optional)
- Docker (optional)
- Prometheus & Grafana (or managed)
- Vault / AWS Secrets Manager / Azure Key Vault

### 2) Environment Variables & Secrets (example)
    export AWS_REGION="us-east-1"
    export CCAF_ENV="production"
    export TF_VAR_admin_email="security@example.com"
    # Secrets are injected at runtime via a secrets manager. Do not hardcode.

### 3) Install Python Dependencies
    python -m venv .venv
    source .venv/bin/activate
    pip install --upgrade pip
    pip install -r requirements.txt

### 4) Bootstrap Orchestration (Phased)
    # Phase 1 — Preparation (inventory & credentials)
    ./scripts/prepare_env.sh

    # Phase 2 — Deploy Infrastructure (IaC)
    cd infrastructure/terraform
    terraform init
    terraform apply -auto-approve

    # Phase 3 — Framework Installation & Services
    ./scripts/install_services.sh

    # Phase 4 — Initial Scan & Baseline Report
    python src/cli.py scan --all --output reports/initial_baseline.json

    # Phase 5 — Enable Continuous Monitoring
    ./scripts/enable_continuous_mode.sh

### 5) Targeted Scan (Example)
    python src/cli.py scan --resource-type s3 --profile org-audit \
      --output reports/s3_scan_$(date +%F).json

### 6) Dashboards (Default Local)
- Prometheus: http://localhost:9090
- Grafana:    http://localhost:3000  (default admin/admin — change immediately)

---

## 🔗 CI/CD Integration (Shift-Left)
- Add a pipeline stage to run policy checks on PRs.
- Enforce gates: **fail** on High/Critical; **ticket** Medium/Low with remediation hints.
- Example GitHub Action job:
    # workflow/ccaf-policy-check.yml
    jobs:
      ccaf-scan:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v3
          - run: python src/cli.py ci-check

- Pre-commit hooks for IaC and policy packs:
    pre-commit run --all-files

---

## 🛡️ Hardening & Operational Guidance
- Start scans with **read-only** credentials; enable remediation via **narrowly-scoped** elevated roles.
- **Separation of duties** between scanning and remediation operators.
- Store all evidence in **immutable** object storage with lifecycle and access logging.
- Enforce **least-privilege** IAM; use **SCPs** (where applicable).
- Maintain **exceptions registry** with expiry, owner, and business justification.
- Sign and timestamp evidence; track provenance and integrity.

---

## 🔍 Audit Reporting & Evidence
- Reports generated to `reports/` in **JSON, CSV, PDF**.
- Each finding contains:
  - Resource identifiers
  - Evidence snapshot (API response, config diff)
  - Control mapping (framework, control ID)
  - Severity, remediation playbook, suggested owner
- Build final audit bundle:
    python src/cli.py generate-report --id <scan_id>

---

## 📈 Observability & Metrics
- Prometheus metrics:
    ccaf_scan_total
    ccaf_finding_count{severity}
    ccaf_remediation_runs_total
- Grafana dashboards:
  - Posture overview
  - Controls-by-status
  - Remediation throughput & MTTR
- Ship logs to SIEM for retention, correlation, and forensics.

---

## 🧭 Compliance Coverage & Mapping (High Level)
- **NIST CSF** — Identify / Protect / Detect / Respond / Recover
- **ISO/IEC 27001:2022** — Annex A mappings & evidence templates
- **CIS Benchmarks** — Cloud provider recommendations
- **PCI-DSS v4.0** — Cardholder data controls in cloud
- **GDPR** — Articles 25, 32, 33 (Data Protection by Design & Default)

See `docs/compliance-matrix.md` for full control-to-rule mappings and evidence requirements.

---

## 🔒 Security, Responsible Disclosure & NDA
**Enterprise disclosure & triage:**
- Report issues to `security@<your-domain>.com` or open a GitHub Issue with the `SECURITY` label.
- **Do not** post PoCs publicly; coordinated disclosure is required.

**MNDA Requirement:**
- For remediation/PoC sharing involving environment access or sensitive artifacts, a **Mutual NDA (MNDA)** is required.
- **Target turnaround: 48 hours**, aligned to typical ISO/NIST incident response SLAs.

**Researchers:**
- Coordinated disclosure **without NDA** is supported per `SECURITY.md`.

---

## 🧪 Testing & Quality Gates
    # Unit tests and static analysis
    pytest tests/
    flake8 src/

- CI runs lints, unit tests, and policy checks on every PR (`.github/workflows/ci.yml`).
- Integration tests target **isolated** accounts/emulators (never production).

---

## 🗺️ Roadmap (Excerpt)
- Multi-account auto-discovery & delegated scanning
- K8s (CIS) policy packs & cluster drift detection
- Evidence notarization and SBOM linkage
- Expanded control libraries (SOC 2, HIPAA, ISO 42001)
- Fine-grained exception SLAs and attestation workflows

---

## 🤝 Contributing & Governance
- Contributions follow `docs/CONTRIBUTING.md` and `docs/CODE_OF_CONDUCT.md`.
- Use GitHub Issues for features/bugs; label security issues as `security`.
- Architectural RFCs live under `design-proposals/`.

---

## 🧾 License (MIT)
    MIT License
    Copyright (c) 2025 Muhammad Arslan Akhtar

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    THE SOFTWARE.

---

## 📚 References & Authoritative Sources
- NIST Cybersecurity Framework — nist.gov
- ISO/IEC 27001:2022 — iso.org
- CIS Benchmarks — cisecurity.org
- PCI Security Standards — pcisecuritystandards.org
- GDPR (Regulation (EU) 2016/679) — eur-lex.europa.eu
- OWASP Top 10 — owasp.org

---

## 📬 Contact & Enterprise Support
**Muhammad Arslan Akhtar**  
Email: arslan@premiumhouseware.co.uk  
LinkedIn: https://www.linkedin.com/in/donutt2u  
GitHub: https://github.com/donutt2u

