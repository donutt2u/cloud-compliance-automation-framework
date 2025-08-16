# Runbook: Handling Non-Compliant Cloud Resource

## Purpose
This runbook describes the process for identifying, triaging, and remediating non-compliant cloud resources discovered by the framework.

---

## Steps

### 1️⃣ Detection
- Framework logs non-compliant resource → `logs/compliance-framework.log`
- Alert sent to Prometheus/Grafana → visible on dashboard

### 2️⃣ Triage
- Check **resource type** (S3, IAM, KMS, etc.)
- Review **policy violation** (e.g., public S3 bucket, missing encryption)
- Assess **severity** (critical, high, medium, low)

### 3️⃣ Response
- If **auto-remediation enabled** → script applies fix
- If manual approval required → follow `scripts/remediation/*`

### 4️⃣ Documentation
- Update `reports/` with incident details
- Map violation to compliance control (ISO 27001, NIST, CIS)

### 5️⃣ Communication
- Notify stakeholders via email/Slack integration
- If severe → escalate to Incident Response team

### 6️⃣ Post-Incident
- Review policies to prevent reoccurrence
- Conduct compliance audit

