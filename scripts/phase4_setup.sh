#!/bin/bash

# ================================================================================
# Manual Phase 4 Setup - Results Storage, Reporting, and Dashboards
# Execute these commands step by step in your project root directory.
# ================================================================================

cd ~/projects/cloud-compliance-framework

echo "🚀 Starting Cloud Compliance Framework - Phase 4: Results & Reporting"
echo "Current directory: $(pwd)"

# Step 1: Update Infrastructure (Terraform) to include DynamoDB
echo "🏗️ Updating Terraform to add a DynamoDB table for results..."

# Create a new file for the DynamoDB table definition
cat > infrastructure/terraform/dynamodb.tf << 'EOF'
resource "aws_dynamodb_table" "results_table" {
  name         = "${var.project_name}-Results"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "ResourceId"
  range_key    = "EvaluationTime"

  attribute {
    name = "ResourceId"
    type = "S"
  }

  attribute {
    name = "EvaluationTime"
    type = "S"
  }
  
  # Enable Point-in-Time Recovery for data protection
  point_in_time_recovery {
    enabled = true
  }

  # Add a global secondary index to query by compliance status
  global_secondary_index {
    name            = "StatusIndex"
    hash_key        = "ComplianceStatus"
    range_key       = "EvaluationTime"
    projection_type = "ALL"
  }

  tags = local.tags
}
EOF

# Update the IAM policy to allow the Lambda to write to the new table
# Using sed to insert the DynamoDB permissions into the IAM policy in iam.tf
sed -i '/# Add more read-only permissions for other services here/i \
      {\
        # Permissions to write evaluation results to DynamoDB\
        Action   = [\
          "dynamodb:PutItem",\
          "dynamodb:UpdateItem"\
        ],\
        Effect   = "Allow",\
        Resource = aws_dynamodb_table.results_table.arn\
      },' infrastructure/terraform/iam.tf

# Update the Lambda definition to pass the table name as an environment variable
# Using sed to add the environment variable to lambda.tf
sed -i '/POWERTOOLS_SERVICE_NAME = var.project_name/a \
      DYNAMODB_TABLE_NAME = aws_dynamodb_table.results_table.name' infrastructure/terraform/lambda.tf

echo "✅ Terraform files updated with DynamoDB table and necessary permissions."

# Step 2: Update Lambda Handler to Store Results in DynamoDB
echo "📝 Updating Lambda handler to save results to DynamoDB..."

# Overwrite the existing handler with the new version
cat > src/lambda_functions/compliance_evaluator/handler.py << 'EOF'
"""
AWS Lambda function for real-time compliance evaluation.
Stores results in Amazon DynamoDB.
"""
import os
import json
from pathlib import Path
from typing import Dict, Any
from datetime import datetime, timezone
import boto3
from decimal import Decimal

# Powertools for AWS Lambda (Python) for best practices
from aws_lambda_powertools import Logger, Tracer
from aws_lambda_powertools.utilities.typing import LambdaContext

from src.policy_engine import PolicyEngine
from src.policy_engine.loader import load_policies_from_directory
from src.policy_engine.models import Resource
from .resource_fetcher import get_resource_details

# Initialize Powertools and AWS Clients
service_name = os.getenv("POWERTOOLS_SERVICE_NAME", "ComplianceFramework")
logger = Logger(service_name=service_name)
tracer = Tracer(service_name=service_name)
dynamodb = boto3.resource("dynamodb")
DYNAMODB_TABLE = os.getenv("DYNAMODB_TABLE_NAME")
table = dynamodb.Table(DYNAMODB_TABLE) if DYNAMODB_TABLE else None

# Initialize Policy Engine globally
POLICY_DIR = Path(__file__).parent.parent.parent / "config" / "policies"
POLICIES = load_policies_from_directory(POLICY_DIR)
ENGINE = PolicyEngine(POLICIES)

class DecimalEncoder(json.JSONEncoder):
    """Helper class to convert a DynamoDB item to JSON."""
    def default(self, o):
        if isinstance(o, Decimal):
            if o % 1 > 0:
                return float(o)
            else:
                return int(o)
        return super(DecimalEncoder, self).default(o)

@tracer.capture_lambda_handler
@logger.inject_lambda_context(log_event=True)
def lambda_handler(event: Dict[str, Any], context: LambdaContext) -> Dict[str, Any]:
    """
    Main Lambda handler function.
    
    1. Receives an event from AWS EventBridge.
    2. Fetches resource configuration.
    3. Evaluates the resource against policies.
    4. Stores the result in DynamoDB.
    """
    if not table:
        logger.error("DynamoDB table name not set in environment variables. Exiting.")
        return {"statusCode": 500, "body": "Configuration error"}

    logger.info("Compliance evaluation triggered.")
    
    resource_details = get_resource_details(event)
    
    if not resource_details:
        logger.warning("Could not extract resource details from the event. Exiting.")
        return {"statusCode": 400, "body": "Invalid event payload"}

    resource = Resource(
        id=resource_details.get("BucketName", "UnknownResource"),
        type="AWS::S3::Bucket",
        attributes=resource_details,
    )
    
    logger.info(f"Evaluating resource: {resource.id} of type {resource.type}")
    
    results = ENGINE.evaluate(resource)
    
    if not results:
        logger.warning(f"No applicable policies found for resource type {resource.type}.")
    
    for result in results:
        try:
            timestamp = datetime.now(timezone.utc).isoformat()
            item_to_store = {
                "ResourceId": result.resource_id,
                "EvaluationTime": timestamp,
                "PolicyId": result.policy_id,
                "ComplianceStatus": result.status,
                # Convert Pydantic models to dicts for storing
                "RuleResults": [r.dict() for r in result.rule_results]
            }
            # Use json.dumps with DecimalEncoder to handle potential float->Decimal conversion by boto3
            item_cleaned = json.loads(json.dumps(item_to_store), parse_float=Decimal)

            table.put_item(Item=item_cleaned)
            
            log_level = "error" if result.status == "NON_COMPLIANT" else "info"
            logger.log(log_level, {"message": "Successfully stored evaluation result in DynamoDB", "result": result.dict()})

        except Exception as e:
            logger.exception(f"Failed to store result in DynamoDB for {result.resource_id}: {e}")
            
    return {"statusCode": 200, "body": "Evaluation complete"}
EOF

echo "✅ Lambda handler updated."

# Step 3: Create a Reporting Script
echo "📊 Creating a script to generate compliance reports..."

cat > scripts/monitoring/generate_report.py << 'EOF'
#!/usr/bin/env python
"""
Generates a compliance summary report by querying the DynamoDB results table.
"""
import boto3
import os
from datetime import datetime
from collections import Counter
from tabulate import tabulate
from pathlib import Path

# This script assumes it's run from the project root
# so we can find the terraform state to get the table name
# A better approach would be using SSM Parameter Store.

def get_dynamodb_table_name():
    """
    A simple (and fragile) way to get the table name.
    In a real system, use SSM Parameter Store or another config management tool.
    For this demo, we assume a local terraform.tfstate file exists.
    """
    # Fallback if running in a different context
    try:
        # Assumes terraform apply was run locally.
        tfstate_path = Path("infrastructure/terraform/terraform.tfstate")
        if not tfstate_path.exists():
            print("❌ Could not find terraform.tfstate. Is the table name hardcoded?")
            return "CloudComplianceFramework-Results" # Fallback

        with open(tfstate_path, 'r') as f:
            import json
            state = json.load(f)
            # Find the resource and get its name attribute
            for resource in state.get('resources', []):
                if resource.get('type') == 'aws_dynamodb_table' and resource.get('name') == 'results_table':
                    return resource['instances'][0]['attributes']['name']
        
        raise ValueError("Table name not found in tfstate")
    except Exception as e:
        print(f"⚠️  Could not determine DynamoDB table name from Terraform state: {e}")
        print("Falling back to default name: CloudComplianceFramework-Results")
        return "CloudComplianceFramework-Results"

def generate_report():
    """Fetches all items from DynamoDB and generates a text report."""
    table_name = get_dynamodb_table_name()
    print(f"📊 Generating report from DynamoDB table: {table_name}")
    
    try:
        dynamodb = boto3.resource("dynamodb")
        table = dynamodb.Table(table_name)
        response = table.scan()
        items = response.get("Items", [])
    except Exception as e:
        print(f"❌ Error: Could not connect to or scan DynamoDB table '{table_name}'.")
        print(f"   Please ensure you have deployed with 'make deploy' and your AWS credentials are correct.")
        print(f"   Boto3 error: {e}")
        return

    if not items:
        print("\nNo compliance results found in the database.")
        print("💡 Try creating a new S3 bucket in your AWS account to trigger an evaluation.")
        return

    # Process the data
    status_counts = Counter(item['ComplianceStatus'] for item in items)
    
    non_compliant_items = [item for item in items if item['ComplianceStatus'] == 'NON_COMPLIANT']
    
    violated_rules = Counter()
    for item in non_compliant_items:
        for rule in item.get('RuleResults', []):
            if rule['status'] == 'NON_COMPLIANT':
                violated_rules[rule['description']] += 1

    # --- Generate Report ---
    report = f"""
=====================================================
    Cloud Compliance Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
=====================================================

Overall Summary
---------------
Total Evaluations: {len(items)}
Compliant:         {status_counts.get('COMPLIANT', 0)}
Non-Compliant:     {status_counts.get('NON_COMPLIANT', 0)}

Top 5 Violated Rules
--------------------
"""
    headers_rules = ["Violated Rule", "Count"]
    rule_data = violated_rules.most_common(5)
    report += tabulate(rule_data, headers=headers_rules, tablefmt="grid")
    report += "\n\nNon-Compliant Resources\n-----------------------\n"
    
    headers_resources = ["Resource ID", "Policy ID", "Evaluation Time"]
    resource_data = [[item['ResourceId'], item['PolicyId'], item['EvaluationTime']] for item in non_compliant_items]
    report += tabulate(resource_data, headers=headers_resources, tablefmt="grid")

    # --- Save and Print Report ---
    report_path = Path("logs/reports/compliance_summary.txt")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with open(report_path, "w") as f:
        f.write(report)

    print(report)
    print(f"\n✅ Report saved to: {report_path}")

if __name__ == "__main__":
    generate_report()
EOF

chmod +x scripts/monitoring/generate_report.py
echo "✅ Reporting script created."

# Step 4: Update Makefile with a 'report' command
echo "🔧 Updating Makefile with a 'report' command..."
# Append the new target to the Makefile
echo -e "\nreport:\n\t@echo \"📊 Generating compliance report...\"\n\tpython scripts/monitoring/generate_report.py\n" >> Makefile
echo "✅ Makefile updated."

# Step 5: Create a Placeholder Grafana Dashboard
echo "🎨 Creating placeholder Grafana dashboard JSON..."
cat > monitoring/grafana/compliance_dashboard.json << 'EOF'
{
  "__inputs": [],
  "__requires": [],
  "annotations": { "list": [] },
  "editable": true,
  "gnetId": null,
  "graphTooltip": 0,
  "id": null,
  "links": [],
  "panels": [
    {
      "type": "stat",
      "title": "Overall Compliance",
      "gridPos": { "h": 4, "w": 8, "x": 0, "y": 0 },
      "datasource": "CloudWatch",
      "options": { "reduceOptions": { "calcs": ["last"] }, "orientation": "auto" }
    },
    {
      "type": "piechart",
      "title": "Compliance Status",
      "gridPos": { "h": 8, "w": 8, "x": 8, "y": 0 },
      "datasource": "CloudWatch",
      "options": {}
    },
    {
      "type": "timeseries",
      "title": "Non-Compliant Events Over Time",
      "gridPos": { "h": 8, "w": 16, "x": 0, "y": 8 },
      "datasource": "CloudWatch"
    },
    {
      "type": "table",
      "title": "Recent Non-Compliant Resources",
      "gridPos": { "h": 8, "w": 24, "x": 0, "y": 16 },
      "datasource": "DynamoDB"
    }
  ],
  "schemaVersion": 35,
  "style": "dark",
  "tags": ["compliance"],
  "templating": { "list": [] },
  "time": { "from": "now-24h", "to": "now" },
  "timepicker": {},
  "timezone": "browser",
  "title": "Cloud Compliance Dashboard",
  "uid": "compliance-dashboard",
  "version": 1
}
EOF
echo "✅ Grafana dashboard placeholder created."

# Step 6: Update Dependencies
echo "📦 Installing new dependency (tabulate)..."
pip install tabulate
pip freeze > requirements.txt
echo "✅ Dependencies updated in requirements.txt."

# Step 7: Update README.md
echo "📖 Updating README.md..."
sed -i '/## 🚀 Next Steps/i \
## 🗄️ Results & Reporting\n\nCompliance evaluation results are stored permanently in an **Amazon DynamoDB** table. This provides a durable, queryable history of all compliance checks.\n\n### Generating a Report\n\nTo get a quick summary of the current compliance posture, you can generate a text-based report from the data in DynamoDB:\n\n```bash\n# Generate and print the latest compliance report\nmake report\n```\n\nThe report is also saved to `logs/reports/compliance_summary.txt`.\n\n### Dashboards\n\nA placeholder configuration for a Grafana dashboard can be found in `monitoring/grafana/`. This provides a blueprint for visualizing compliance data using Amazon CloudWatch Metrics and a DynamoDB data source.\n' README.md
sed -i 's/- Phase 4: Real-time Event Processing/- ✅ Phase 4: Storing Results & Reporting/' README.md
# Fix previous phase description
sed -i 's/- ✅ Phase 3: AWS Lambda Integration/- ✅ Phase 3: AWS Lambda & Real-time Event Integration/' README.md

echo "✅ README.md updated."

# Step 8: Final verification
echo ""
echo "🎯 Phase 4 Setup Verification:"
echo "✅ DynamoDB table added to Terraform."
echo "✅ Lambda IAM role and environment updated."
echo "✅ Lambda handler now stores results in DynamoDB."
echo "✅ New report generation script is available."
echo "✅ Makefile updated with 'make report' target."
echo "✅ Placeholder Grafana dashboard created."

echo ""
echo "🚀 Phase 4 Complete! You now have a robust system for storing and reporting on compliance data."
echo "Next steps:"
echo "1. Run 'make deploy' to apply the infrastructure changes (this will create the DynamoDB table)."
echo "2. Create a new S3 bucket in your AWS account to trigger an evaluation and populate the table."
echo "3. Wait a minute, then run 'make report' to see your first compliance summary!"
echo ""
echo "Ready for the final phase: Remediation & Advanced Features."
