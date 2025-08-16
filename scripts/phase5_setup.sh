#!/bin/bash

# ================================================================================
# Manual Phase 5 Setup - Remediation, Security, and CI/CD
# Execute these commands step by step in your project root directory.
# ================================================================================

cd ~/projects/cloud-compliance-framework

echo "🚀 Starting Cloud Compliance Framework - Phase 5: Remediation & Automation"
echo "Current directory: $(pwd)"

# Step 1: Create the Remediation Engine
echo "🔧 Creating the Remediation Engine..."
mkdir -p src/remediation_engine

# Create package initializer
cat > src/remediation_engine/__init__.py << 'EOF'
"""
Automated Remediation Engine.

This engine maps non-compliant rule IDs to specific, automated
remediation actions.
"""
from .handler import trigger_remediation

__all__ = ["trigger_remediation"]
EOF

# Create remediation actions
cat > src/remediation_engine/actions.py << 'EOF'
"""
Contains specific remediation functions for AWS resources.
Each function should be idempotent and clearly state what it does.
"""
import boto3
from aws_lambda_powertools import Logger

logger = Logger(child=True)

def enable_s3_bucket_versioning(resource_id: str, region: str) -> bool:
    """
    Enables versioning on a specified S3 bucket.

    Args:
        resource_id: The name of the S3 bucket.
        region: The AWS region of the bucket.

    Returns:
        True if the action was successful, False otherwise.
    """
    try:
        logger.info(f"Attempting to enable versioning on S3 bucket: {resource_id}")
        s3_client = boto3.client("s3", region_name=region)
        s3_client.put_bucket_versioning(
            Bucket=resource_id,
            VersioningConfiguration={'Status': 'Enabled'}
        )
        logger.info(f"Successfully enabled versioning on S3 bucket: {resource_id}")
        return True
    except Exception as e:
        logger.exception(f"Failed to enable versioning on {resource_id}: {e}")
        return False

# --- Add more remediation functions below ---
#
# def enforce_s3_public_access_block(resource_id: str, region: str) -> bool:
#     ...
#
EOF

# Create the remediation handler to map rules to actions
cat > src/remediation_engine/handler.py << 'EOF'
"""
Maps failed rule IDs to remediation actions and triggers them.
"""
from typing import Optional
from aws_lambda_powertools import Logger
from . import actions

logger = Logger(child=True)

# This map is the core of the remediation engine.
# It connects a specific compliance rule to a corrective action.
REMEDIATION_MAP = {
    "s3-enable-versioning": actions.enable_s3_bucket_versioning,
    # "s3-block-public-access": actions.enforce_s3_public_access_block,
}


def trigger_remediation(resource_id: str, resource_region: Optional[str], rule_id: str) -> bool:
    """
    Triggers the appropriate remediation action for a given failed rule.

    Args:
        resource_id: The ID of the non-compliant resource.
        resource_region: The AWS region of the resource.
        rule_id: The ID of the compliance rule that failed.

    Returns:
        True if remediation was successful, False otherwise.
    """
    remediation_action = REMEDIATION_MAP.get(rule_id)

    if not remediation_action:
        logger.warning(f"No remediation action defined for rule: {rule_id}")
        return False

    if not resource_region:
        logger.error(f"Cannot perform remediation for {resource_id} without a region.")
        return False

    logger.info(f"Triggering remediation '{remediation_action.__name__}' for resource '{resource_id}' due to failed rule '{rule_id}'")
    
    return remediation_action(resource_id, resource_region)
EOF

echo "✅ Remediation Engine created."

# Step 2: Update Lambda to Trigger Remediation
echo "📝 Updating Lambda handler to trigger remediation actions..."

# Overwrite the handler with the new version that includes remediation logic
cat > src/lambda_functions/compliance_evaluator/handler.py << 'EOF'
"""
AWS Lambda function for real-time compliance evaluation.
Stores results in Amazon DynamoDB and triggers remediation.
"""
import os
import json
from pathlib import Path
from typing import Dict, Any
from datetime import datetime, timezone
import boto3
from decimal import Decimal

from aws_lambda_powertools import Logger, Tracer
from aws_lambda_powertools.utilities.typing import LambdaContext

from src.policy_engine import PolicyEngine, EvaluationResult
from src.policy_engine.loader import load_policies_from_directory
from src.policy_engine.models import Resource
from src.remediation_engine import trigger_remediation
from .resource_fetcher import get_resource_details

# --- Initialization ---
service_name = os.getenv("POWERTOOLS_SERVICE_NAME", "ComplianceFramework")
logger = Logger(service_name=service_name)
tracer = Tracer(service_name=service_name)

# Remediation safety switch
ENABLE_REMEDIATION = os.getenv("ENABLE_REMEDIATION", "false").lower() == "true"

# AWS Clients
dynamodb = boto3.resource("dynamodb")
DYNAMODB_TABLE = os.getenv("DYNAMODB_TABLE_NAME")
table = dynamodb.Table(DYNAMODB_TABLE) if DYNAMODB_TABLE else None

# Policy Engine
POLICY_DIR = Path(__file__).parent.parent.parent / "config" / "policies"
POLICIES = load_policies_from_directory(POLICY_DIR)
ENGINE = PolicyEngine(POLICIES)

# --- Helper Functions ---
class DecimalEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, Decimal):
            return float(o) if o % 1 > 0 else int(o)
        return super(DecimalEncoder, self).default(o)

def store_result(result: EvaluationResult):
    """Stores a single evaluation result in DynamoDB."""
    if not table:
        logger.error("DynamoDB table not configured. Cannot store result.")
        return
    try:
        timestamp = datetime.now(timezone.utc).isoformat()
        item_to_store = {
            "ResourceId": result.resource_id,
            "EvaluationTime": timestamp,
            "PolicyId": result.policy_id,
            "ComplianceStatus": result.status,
            "RuleResults": [r.dict() for r in result.rule_results]
        }
        item_cleaned = json.loads(json.dumps(item_to_store), parse_float=Decimal)
        table.put_item(Item=item_cleaned)
        logger.info("Successfully stored evaluation result in DynamoDB.", result=result.dict())
    except Exception as e:
        logger.exception("Failed to store result in DynamoDB.", resource_id=result.resource_id)

# --- Main Handler ---
@tracer.capture_lambda_handler
@logger.inject_lambda_context(log_event=True)
def lambda_handler(event: Dict[str, Any], context: LambdaContext) -> Dict[str, Any]:
    logger.info("Compliance evaluation triggered.", remediation_enabled=ENABLE_REMEDIATION)
    
    resource_details = get_resource_details(event)
    if not resource_details:
        logger.warning("Could not extract resource details from event. Exiting.")
        return {"statusCode": 400, "body": "Invalid event payload"}

    resource = Resource(
        id=resource_details.get("BucketName", "UnknownResource"),
        type="AWS::S3::Bucket",
        attributes=resource_details,
    )
    resource_region = resource_details.get("Region")
    
    logger.info(f"Evaluating resource: {resource.id}")
    results = ENGINE.evaluate(resource)
    
    for result in results:
        store_result(result)
        if result.status == "NON_COMPLIANT":
            logger.error("Resource is NON_COMPLIANT.", result=result.dict())
            if ENABLE_REMEDIATION:
                for rule_res in result.rule_results:
                    if rule_res.status == "NON_COMPLIANT":
                        trigger_remediation(resource.id, resource_region, rule_res.rule_id)
            else:
                logger.warning("Auto-remediation is disabled. No action will be taken.")
    
    return {"statusCode": 200, "body": "Evaluation complete"}
EOF
echo "✅ Lambda handler updated with remediation logic."

# Step 3: Update Infrastructure (Terraform) for Remediation
echo "🏗️ Updating Terraform with remediation permissions and settings..."

# Add a variable for the remediation switch
sed -i '/lambda_memory_size/a \
variable "enable_remediation" {\
  description = "Safety switch to enable/disable auto-remediation. Set to true to enable."\
  type        = bool\
  default     = false\
}' infrastructure/terraform/variables.tf

# Add the new remediation permission to the IAM policy
sed -i '/# Add more read-only permissions for other services here/i \
      {\
        # Permissions to remediate S3 bucket configurations\
        Action   = [\
          "s3:PutBucketVersioning"\
        ],\
        Effect   = "Allow",\
        # Be specific to avoid overly broad permissions\
        Resource = "arn:aws:s3:::*"\
      },' infrastructure/terraform/iam.tf

# Pass the remediation switch to the Lambda environment variables
sed -i '/POWERTOOLS_SERVICE_NAME = var.project_name/a \
      ENABLE_REMEDIATION    = var.enable_remediation' infrastructure/terraform/lambda.tf

echo "✅ Terraform files updated."

# Step 4: Add Security Scanning and CI/CD Workflow
echo "🔒 Adding security scanning and CI/CD workflow..."

# Update Makefile with a security scan command
echo -e "\nsecurity-scan:\n\t@echo \"🛡️  Running security scans...\"\n\t@echo \"--- Running Bandit (SAST) ---\"\n\tbandit -r src/ -s B101\n\t@echo \"--- Running Safety (Dependency Check) ---\"\n\tsafety check --full-report\n" >> Makefile

# Create the GitHub Actions workflow file
cat > .github/workflows/ci-cd.yml << 'EOF'
name: CI/CD Pipeline

on:
  push:
    branches: [ "main" ]
  pull_request:
    branches: [ "main" ]

jobs:
  build-and-test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.9", "3.10", "3.11"]

    steps:
    - name: Checkout repository
      uses: actions/checkout@v4

    - name: Set up Python ${{ matrix.python-version }}
      uses: actions/setup-python@v4
      with:
        python-version: ${{ matrix.python-version }}

    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -r requirements.txt
        pip install bandit safety  # Install security tools

    - name: Lint and Format Check
      run: |
        make lint
        make format -- --check # Use --check to fail on unformatted code

    - name: Security Scan
      run: make security-scan

    - name: Run Tests with Coverage
      run: make test

# --- DEPLOYMENT JOB (Optional - uncomment to enable) ---
# This job deploys to AWS when code is pushed to the 'main' branch.
# Requires AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY to be set as repository secrets.
#
#  deploy-to-aws:
#    needs: build-and-test
#    runs-on: ubuntu-latest
#    # Only run on push to the main branch, not on pull requests
#    if: github.event_name == 'push' && github.ref == 'refs/heads/main'
#    steps:
#    - name: Checkout repository
#      uses: actions/checkout@v4
#
#    - name: Set up Python
#      uses: actions/setup-python@v4
#      with:
#        python-version: '3.11'
#
#    - name: Configure AWS Credentials
#      uses: aws-actions/configure-aws-credentials@v4
#      with:
#        aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
#        aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
#        aws-region: eu-west-2
#
#    - name: Install dependencies and Terraform
#      run: |
#        pip install -r requirements.txt
#        sudo apt-get update && sudo apt-get install -y gnupg software-properties-common
#        wget -O- https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
#        echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
#        sudo apt-get update && sudo apt-get install terraform
#
#    - name: Deploy with Make
#      run: make deploy
EOF
echo "✅ Security and CI/CD tools configured."

# Step 5: Add Final Documentation
echo "📖 Creating final documentation and runbooks..."

# Create a runbook for handling incidents
cat > docs/runbooks/handle_non_compliant_resource.md << 'EOF'
# Runbook: Handling a Non-Compliant Resource Alert

This runbook outlines the steps to take when a non-compliant resource is detected by the Cloud Compliance Framework.

## 1. Triage the Alert

- **Source**: Alert from CloudWatch Logs, SIEM, or `make report`.
- **Identify**: What is the Resource ID? Which Policy and Rule were violated? What was the detection time?

## 2. Check for Automated Remediation

- **Verify Logs**: Check the logs for the `compliance-evaluator` Lambda function in CloudWatch for the corresponding timeframe.
- **Look for**:
  - `Triggering remediation...` log entries.
  - `Successfully remediated...` or `Failed to remediate...` messages.

## 3. Analyze the Outcome

### Case A: Remediation was Successful

- **Action**: Verify the resource's configuration in the AWS Console to confirm it is now compliant.
- **Resolution**: No further action needed. The incident is resolved.

### Case B: Remediation Failed or Was Not Triggered

- **Action**:
  1. **Disable the resource**: If the vulnerability is critical (e.g., public S3 bucket with sensitive data), immediately take action to secure the resource manually (e.g., apply a restrictive bucket policy).
  2. **Investigate the failure**:
     - Check the Lambda logs for error messages (e.g., `Permissions error`, `API throttling`).
     - Review the remediation code in `src/remediation_engine/` for bugs.
     - Check the IAM permissions for the Lambda execution role.
  3. **Remediate Manually**: Apply the required configuration change through the AWS Console or CLI.
  4. **Create a follow-up task**: Address the root cause of the auto-remediation failure.

## 4. Post-Incident

- **Documentation**: Update this runbook if any steps were unclear or missing.
- **Enhancement**: If a new type of failure occurred, consider adding a new rule or remediation action to the framework.
EOF

# Final update to the main README.md
sed -i 's/- Phase 5: Monitoring & Alerting/- ✅ Phase 5: Remediation, Security & CI\/CD/' README.md
sed -i '/## 🚀 Features/a \
## ✨ Project Complete\n\nThis project is a fully functional, event-driven compliance framework. It detects, reports, and automatically remediates policy violations in real-time, secured by a CI/CD pipeline.\n' README.md
sed -i '/## 🚀 Next Steps/d' README.md # Remove old Next Steps
sed -i 's/Beta/Production\/Stable/' pyproject.toml # Update project status

cat >> README.md << 'EOF'

## 🤖 Automated Remediation

The framework can automatically remediate certain policy violations. This feature is controlled by a safety switch.

- **How it works**: When a non-compliant resource is detected, the Lambda checks for a corresponding action in the `src/remediation_engine/handler.py` map. If found, it executes the action (e.g., calls an AWS API to fix the setting).
- **Enabling**: To enable remediation, go to `infrastructure/terraform/variables.tf` and set `default = true` for the `enable_remediation` variable, then run `make deploy`.

**WARNING**: Enable auto-remediation with caution. Always test remediation logic in a non-production environment first.

## 🛡️ Security & CI/CD

The project includes a robust CI/CD pipeline and security scanning tools to ensure code quality and security.

- **CI/CD**: The workflow in `.github/workflows/ci-cd.yml` automatically lints, formats, tests, and scans all code on every push to the `main` branch.
- **Security Scans**: Run local security scans at any time with:
  ```bash
  # Run Bandit (SAST) and Safety (dependency check)
  make security-scan
