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
