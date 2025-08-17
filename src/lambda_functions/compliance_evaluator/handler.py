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
            "RuleResults": [r.dict() for r in result.rule_results],
        }
        item_cleaned = json.loads(json.dumps(item_to_store), parse_float=Decimal)
        table.put_item(Item=item_cleaned)
        logger.info(
            "Successfully stored evaluation result in DynamoDB.", result=result.dict()
        )
    except Exception as e:
        logger.exception(
            "Failed to store result in DynamoDB.", resource_id=result.resource_id
        )


# --- Main Handler ---
@tracer.capture_lambda_handler
@logger.inject_lambda_context(log_event=True)
def lambda_handler(event: Dict[str, Any], context: LambdaContext) -> Dict[str, Any]:
    logger.info(
        "Compliance evaluation triggered.", remediation_enabled=ENABLE_REMEDIATION
    )

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
                        trigger_remediation(
                            resource.id, resource_region, rule_res.rule_id
                        )
            else:
                logger.warning("Auto-remediation is disabled. No action will be taken.")

    return {"statusCode": 200, "body": "Evaluation complete"}
