# 🌐 Cloud Compliance Automation Framework (CCAF)

![Status](https://img.shields.io/badge/status-active-success.svg)  
![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)  
![Build](https://img.shields.io/badge/build-passing-brightgreen.svg)  
![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)

---

## 🚀 Enterprise Overview
**Cloud Compliance Automation Framework (CCAF)** is an enterprise-grade, modular platform for **continuous compliance-as-code**, automated evidence collection, and policy-driven remediation across multi-cloud estates (AWS, Azure, GCP). CCAF codifies security controls and compliance requirements into repeatable, auditable pipelines so organizations can operationalize risk reduction at scale.

Core goals:
- Provide **real-time compliance posture** and drift detection.
- Enable **audit-ready evidence** mapped to controls (ISO/IEC 27001, NIST CSF, CIS, PCI-DSS, GDPR).
- Integrate directly into DevSecOps pipelines for **shift-left** enforcement and automated remediation.
- Support enterprise governance: RBAC, secure secrets handling, logging, and audit trails.

---

## ✨ Key Capabilities (Executive Summary)
- **Policy-as-Code Engine**: Modular rules engine with support for custom and framework-aligned rule packs.  
- **Automated Scanning**: Resource inventory + continuous scanning for misconfigurations (IAM, storage, networking, KMS, logging).  
- **Remediation-as-Code**: Safe, idempotent remediation playbooks with approval gating and rollback.  
- **Audit Reporting**: Automated generation of evidence bundles (JSON, CSV, PDF) mapped to regulatory controls.  
- **Observability & Dashboards**: Grafana dashboards with Prometheus metrics for posture, trends, and SLA monitoring.  
- **IaC Integration**: Terraform / CloudFormation / ARM / Pulumi modules & pre-commit checks for IaC security.  
- **Pipeline Integrations**: Native GitHub Actions, GitLab CI, Jenkins pipelines for policy checks pre-merge.  
- **Operational Runbooks**: Incident playbooks, forensics evidence extraction, and recommended remediation steps.  
- **Security-First Design**: Zero-trust principles, least-privilege defaults, secret handling via vaults.

---

## 📌 Audience
- Security & Cloud Architects
- DevSecOps and Platform Engineers
- Compliance, Audit & Risk teams
- Managed Security Service Providers (MSSPs)

---

## 📂 Repository Structure

`
cloud-compliance-framework/
├── build/              # Build automation artifacts
├── config/             # Policy sets, templates, env configs
│   ├── environments/   # Local/dev/prod configs (YAML/JSON)
│   └── policies/       # Compliance policies & mappings
├── docs/               # Documentation, runbooks, compliance matrix
├── infrastructure/     # Terraform, CloudFormation, Ansible templates
├── logs/               # Log outputs of scans and framework runs
├── monitoring/         # Prometheus + Grafana dashboards
├── reports/            # Auto-generated compliance reports
├── scripts/            # Setup, automation, orchestration scripts
├── src/                # Core framework (policy engine, remediation, utils)
├── tests/              # Unit, integration & end-to-end tests
└── requirements.txt    # Python dependencies
`
---

## 🏗️ Deployment Guide
> This section is intentionally presented as a single contiguous set of instructions and examples suitable for copying into a `README.md` or runbook. Follow enterprise change control and run in non-production or isolated environments first.

### 1. Prerequisites (Enterprise baseline)
- Python **3.11+** (use virtualenv / venv)  
- Non-root **IAM user** or service principal with scoped permissions for scanning & remediation. Never use cloud root accounts.  
- **Terraform** (recommended >= 1.4) and **Ansible** (optional)  
- **Docker** (optional) for containerised components  
- Grafana & Prometheus (or managed equivalents) for monitoring and visualisation  
- Vault / Secrets manager for credentials (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault)

### 2. Environment variables & secrets (example)
Set required variables in your CI/CD secret store or runner environment:
    export AWS_REGION="us-east-1"
    export CCAF_ENV=" production"
    export TF_VAR_admin_email="security@example.com"
    # Secrets should be injected at runtime from a secret manager; do not hardcode.

### 3. Install Python dependencies
    python -m venv .venv
    source .venv/bin/activate
    pip install --upgrade pip
    pip install -r requirements.txt

### 4. Bootstrap orchestration (Phased execution)
Phase 1 — Preparation (inventory & credentials)
    ./scripts/prepare_env.sh
Phase 2 — Deploy Infrastructure (IaC)
    cd infrastructure/terraform
    terraform init
    terraform apply -auto-approve
Phase 3 — Framework Installation & Services
    ./scripts/install_services.sh
Phase 4 — Initial Scan & Baseline Report
    python src/cli.py scan --all --output reports/initial_baseline.json
Phase 5 — Enable Continuous Monitoring
    ./scripts/enable_continuous_mode.sh

### 5. Example: run a targeted scan
    python src/cli.py scan --resource-type s3 --profile org-audit --output reports/s3_scan_$(date +%F).json

### 6. Viewing dashboards (default local)
- Prometheus: http://localhost:9090  
- Grafana:  http://localhost:3000  *(default admin/admin — change immediately)*

### 7. Integrating with CI/CD
- Add a pipeline stage to run policy checks on PRs:
    - Check IaC templates with pre-commit hooks and `ccaf policy check` command.
    - Fail the pipeline for high/critical findings; create tickets for medium/low with automated remediation suggestions.
- Example action: add `workflow/ccaf-policy-check.yml` with a job that executes `python src/cli.py ci-check`.

### 8. Hardening & Operational Guidance
- Run scans using a **read-only** credential first; only enable remediation with an elevated, narrowly-scoped role and approval workflow.
- Maintain separation of duties: scanners vs remediation operators.
- Store all audit evidence in an immutable object store with lifecycle and access logging.
- Enforce least-privilege IAM and use service control policies where available.

---

## 🔍 Audit Reporting & Evidence
- Reports are generated to `reports/` as structured JSON, CSV, and human-readable PDF summaries.
- Each finding includes:
  - Resource identifier(s)
  - Evidence snapshot (API response, config diff)
  - Control mapping (framework, control ID)
  - Risk rating, remediation playbook, suggested owner
- Use the `src/cli.py generate-report --id <scan_id>` to build the final audit bundle.

---

## 🔒 Security, Responsible Disclosure & NDA
**Enterprise disclosure & triage policy**
- For vulnerability reports and PoCs, contact `security@<your-domain>.com` or open an issue with `SECURITY` label. Do **not** post PoC publicly.  
- **NDA requirement for engaged remediation/PoC sharing:** For any coordinated remediation work where we must access your environments or share sensitive PoCs, an executed Mutual Non-Disclosure Agreement (MNDA) is required. **Target turnaround for MNDA execution: 48 hours** from request. This timeframe aligns with incident response SLAs used by many enterprise risk frameworks (ISO 27001, NIST).  
- If you are a security researcher and want coordinated disclosure without an NDA, follow the policy in `SECURITY.md`. We accept responsibly disclosed vulnerabilities and reward meaningful reports per our bug bounty / triage process.

---

## 🧪 Testing & CI
- Unit tests and static analysis:
    pytest tests/
    flake8 src/
- CI: GitHub Actions pipeline runs tests, lints, and policy checks for each PR. See `.github/workflows/ci.yml`.
- Integration tests are executed against isolated test accounts or emulators (do not use production).

---

## 📈 Observability & Metrics
- Prometheus metrics exported by the scanner and remediation engine include:
  - `ccaf_scan_total`, `ccaf_finding_count{severity}`, `ccaf_remediation_runs_total`
- Grafana dashboards provide:
  - Posture overview, controls-by-status, remediation throughput, mean-time-to-remediated (MTTR)
- Centralised logs should be shipped to SIEM for long-term retention and forensic workflows.

---

## 🔁 Compliance Coverage & Mapping (high-level)
- **NIST CSF** — Identify, Protect, Detect, Respond, Recover; mapping available in `docs/compliance-matrix.md`.  
- **ISO/IEC 27001** — Annexe A control mappings and evidence templates included.  
- **CIS Benchmarks** — Modules for cloud provider CIS recommendations.  
- **PCI-DSS v4.0** — Selected cardholder-data relevant controls for cloud deployments.  
- **GDPR** — Data Protection by Design & Default (Articles 25, 32, 33) guidance included.

Refer to `docs/` for the full control-to-rule mappings and evidence requirements.

---

## 🤝 Contributing & Governance
- Follow `docs/CONTRIBUTING.md` and `docs/CODE_OF_CONDUCT.md`.  
- Submit feature requests and issues via GitHub Issues; label changes and security issues as `security`.  
- Use the `design-proposals/` folder for architectural RFCs and major design discussions.

---

## 🧾 License
This project is released under the **MIT License**.

Copyright (c) 2025 Muhammad Arslan Akhtar

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including, without limitation, the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.


---

## 📚 References & Authoritative Sources
- NIST Cybersecurity Framework — NIST publications (NIST.gov)  
- ISO/IEC 27001:2022 — International Organization for Standardization (ISO.org)  
- CIS Benchmarks — Center for Internet Security (cisecurity.org)  
- PCI Security Standards — pcisecuritystandards.org  
- GDPR — eur-lex.europa.eu (Regulation (EU) 2016/679)  
- OWASP Top 10 — owasp.org

---

## 📬 Contact & Enterprise Support
For enterprise support, professional services, or security incident engagement:
**Muhammad Arslan Akhtar**  
Email: arslan@premiumhouseware.co.uk  
LinkedIn: https://www.linkedin.com/in/donutt2u  
GitHub: https://github.com/donutt2u

