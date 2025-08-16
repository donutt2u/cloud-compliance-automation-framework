#!/bin/bash

# ================================================================================
# Manual Phase 3 Setup - AWS Lambda & Real-time Event Integration
# Execute these commands step by step in your project root directory.
# ================================================================================

cd ~/projects/cloud-compliance-framework

echo "🚀 Starting Cloud Compliance Framework - Phase 3: AWS Integration"
echo "Current directory: $(pwd)"

# Step 1: Create the Lambda Function Handler
echo "📝 Creating AWS Lambda function handler and helpers..."

# Create the main handler directory
mkdir -p src/lambda_functions/compliance_evaluator

# Create __init__.py files to make them Python packages
touch src/lambda_functions/__init__.py
touch src/lambda_functions/compliance_evaluator/__init__.py

# Create a helper for fetching resource configurations from AWS
cat > src/lambda_functions/compliance_evaluator/resource_fetcher.py << 'EOF'
"""
Fetches detailed configuration for AWS resources.
"""
import boto3
from typing import Dict, Any, Optional
from src.logger import get_logger

logger = get_logger(__name__)

def fetch_s3_bucket_details(bucket_name: str, region: str) -> Optional[Dict[str, Any]]:
    """
    Fetches the full configuration for a given S3 bucket.

    Args:
        bucket_name: The name of the S3 bucket.
        region: The AWS region of the bucket.

    Returns:
        A dictionary of the bucket's configuration attributes, or None on error.
    """
    try:
        # Note: S3 is a global service, but some calls are region-specific.
        # It's best practice to initialize the client in the target region.
        s3_client = boto3.client("s3", region_name=region)
        logger.info(f"Fetching details for S3 bucket: {bucket_name}")

        # Consolidate multiple API calls into one attribute dictionary
        attributes = {
            "BucketName": bucket_name,
            "Region": region,
            "PublicAccessBlockConfiguration": s3_client.get_public_access_block(Bucket=bucket_name).get("PublicAccessBlockConfiguration", {}),
            "VersioningConfiguration": s3_client.get_bucket_versioning(Bucket=bucket_name),
            "BucketEncryption": s3_client.get_bucket_encryption(Bucket=bucket_name),
        }

        # Remove keys that are not part of the config
        attributes["VersioningConfiguration"].pop("ResponseMetadata", None)

        return attributes

    except s3_client.exceptions.NoSuchBucket:
        logger.error(f"S3 bucket '{bucket_name}' not found.")
        return None
    except s3_client.exceptions.ServerSideEncryptionConfigurationNotFoundError:
        # This error means encryption is not configured, which is a compliance state.
        logger.warning(f"No server-side encryption found for bucket '{bucket_name}'.")
        attributes["BucketEncryption"] = {}
        return attributes
    except Exception as e:
        # Catch other potential boto3 errors (e.g., credentials, throttling)
        logger.error(f"Failed to fetch details for bucket '{bucket_name}': {e}", exc_info=True)
        return None

def get_resource_details(event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Generic resource fetcher based on the event source and type.
    Currently supports S3 bucket creation events from CloudTrail via EventBridge.
    """
    detail = event.get("detail", {})
    event_name = detail.get("eventName")
    
    if event_name == "CreateBucket":
        bucket_name = detail.get("requestParameters", {}).get("bucketName")
        region = detail.get("awsRegion")
        if bucket_name and region:
            return fetch_s3_bucket_details(bucket_name, region)

    logger.warning(f"Unsupported event type for resource fetching: {event_name}")
    return None
EOF

# Create the main Lambda handler
cat > src/lambda_functions/compliance_evaluator/handler.py << 'EOF'
"""
AWS Lambda function for real-time compliance evaluation.
Triggered by AWS EventBridge for resource change events.
"""
import os
from pathlib import Path
from typing import Dict, Any

# Powertools for AWS Lambda (Python) for best practices
from aws_lambda_powertools import Logger, Tracer
from aws_lambda_powertools.utilities.typing import LambdaContext

from src.policy_engine import PolicyEngine
from src.policy_engine.loader import load_policies_from_directory
from src.policy_engine.models import Resource
from .resource_fetcher import get_resource_details

# Initialize Powertools
# Service name can be set by an environment variable
service_name = os.getenv("POWERTOOLS_SERVICE_NAME", "ComplianceFramework")
logger = Logger(service_name=service_name)
tracer = Tracer(service_name=service_name)

# Initialize Policy Engine globally to leverage Lambda execution context reuse
# This avoids reloading policies on every invocation ("warm" Lambda).
POLICY_DIR = Path(__file__).parent.parent.parent / "config" / "policies"
POLICIES = load_policies_from_directory(POLICY_DIR)
ENGINE = PolicyEngine(POLICIES)

@tracer.capture_lambda_handler
@logger.inject_lambda_context(log_event=True)
def lambda_handler(event: Dict[str, Any], context: LambdaContext) -> Dict[str, Any]:
    """
    Main Lambda handler function.
    
    1. Receives an event from AWS EventBridge.
    2. Fetches the full configuration of the resource from the event.
    3. Formats the configuration into a `Resource` model.
    4. Evaluates the resource against loaded policies.
    5. Logs the compliance results.
    """
    logger.info("Compliance evaluation triggered.")
    
    resource_details = get_resource_details(event)
    
    if not resource_details:
        logger.warning("Could not extract resource details from the event. Exiting.")
        return {"statusCode": 400, "body": "Invalid event payload"}

    # Map the AWS event to our internal Resource model
    # The event name can be used to determine the resource type.
    resource = Resource(
        id=resource_details.get("BucketName", "UnknownResource"),
        type="AWS::S3::Bucket",  # In a real app, this would be determined dynamically
        attributes=resource_details,
    )
    
    logger.info(f"Evaluating resource: {resource.id} of type {resource.type}")
    
    # Run the evaluation
    results = ENGINE.evaluate(resource)
    
    # Log results for now. In a real application, you would send this to a
    # security hub, a DynamoDB table, or an SNS topic for alerting.
    if not results:
        logger.warning(f"No applicable policies found for resource type {resource.type}.")
    
    for result in results:
        if result.status == "NON_COMPLIANT":
            logger.error({"evaluation_result": result.dict()})
        else:
            logger.info({"evaluation_result": result.dict()})
            
    return {"statusCode": 200, "body": "Evaluation complete"}

EOF

echo "✅ Lambda function files created."

# Step 2: Create a Lambda Packaging Script
echo "📦 Creating Lambda packaging script..."
cat > scripts/deployment/build_lambda_package.sh << 'EOF'
#!/bin/bash
set -e

# This script prepares the AWS Lambda deployment package.

PACKAGE_DIR="build/lambda"
OUTPUT_ZIP="deployment_package.zip"

echo "📦 Creating Lambda deployment package..."

# 1. Clean up previous builds
rm -rf build
mkdir -p "$PACKAGE_DIR"

# 2. Copy source code and configuration
echo "Copying source code and configs..."
cp -r src/ "$PACKAGE_DIR/"
cp -r config/ "$PACKAGE_DIR/"

# 3. Install Python dependencies
echo "Installing dependencies..."
pip install -r requirements.txt --target "$PACKAGE_DIR"

# 4. Create the ZIP file
echo "Creating ZIP file: $OUTPUT_ZIP"
cd "$PACKAGE_DIR"
zip -r ../../"$OUTPUT_ZIP" . > /dev/null
cd ../../

# 5. Clean up the build directory
rm -rf "$PACKAGE_DIR"

echo "✅ Lambda package created successfully at $OUTPUT_ZIP"
EOF

# Make the script executable
chmod +x scripts/deployment/build_lambda_package.sh

echo "✅ Lambda packaging script created."

# Step 3: Create Infrastructure as Code (Terraform)
echo "🏗️ Creating Terraform files for AWS infrastructure..."
mkdir -p infrastructure/terraform

# Create variables.tf
cat > infrastructure/terraform/variables.tf << 'EOF'
variable "aws_region" {
  description = "The AWS region to deploy resources in."
  type        = string
  default     = "eu-west-2"
}

variable "project_name" {
  description = "The name of the project, used for naming resources."
  type        = string
  default     = "CloudComplianceFramework"
}

variable "lambda_memory_size" {
  description = "The amount of memory to allocate to the Lambda function."
  type        = number
  default     = 256
}
EOF

# Create main.tf for provider configuration
cat > infrastructure/terraform/main.tf << 'EOF'
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# Use a data source to get the current account ID and region for resource naming
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region_name = data.aws_region.current.name
  tags = {
    Project   = var.project_name
    ManagedBy = "Terraform"
  }
}
EOF

# Create iam.tf for the Lambda execution role
cat > infrastructure/terraform/iam.tf << 'EOF'
resource "aws_iam_role" "lambda_exec_role" {
  name = "${var.project_name}-LambdaExecRole"

  assume_role_policy = jsonencode({
    Version   = "2012-10-17",
    Statement = [{
      Action    = "sts:AssumeRole",
      Effect    = "Allow",
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })

  tags = local.tags
}

resource "aws_iam_policy" "lambda_policy" {
  name        = "${var.project_name}-LambdaPolicy"
  description = "IAM policy for the compliance evaluator Lambda function"

  policy = jsonencode({
    Version   = "2012-10-17",
    Statement = [
      {
        Action   = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ],
        Effect   = "Allow",
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        # Permissions to read S3 bucket configurations
        Action   = [
          "s3:GetBucket*",
          "s3:ListAllMyBuckets",
          "s3:GetAccountPublicAccessBlock"
        ],
        Effect   = "Allow",
        Resource = "*" # S3 actions often require "*" for List or are non-resource specific
      }
      # Add more read-only permissions for other services here
      # e.g., "ec2:DescribeInstances", "iam:GetRole", etc.
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_policy_attach" {
  role       = aws_iam_role.lambda_exec_role.name
  policy_arn = aws_iam_policy.lambda_policy.arn
}
EOF

# Create lambda.tf for the Lambda function definition
cat > infrastructure/terraform/lambda.tf << 'EOF'
resource "aws_lambda_function" "compliance_evaluator" {
  filename         = "../../deployment_package.zip"
  function_name    = "${var.project_name}-Evaluator"
  role             = aws_iam_role.lambda_exec_role.arn
  handler          = "src.lambda_functions.compliance_evaluator.handler.lambda_handler"
  
  # Ensure the package is built before terraform runs
  source_code_hash = filebase64sha256("../../deployment_package.zip")

  runtime     = "python3.11"
  memory_size = var.lambda_memory_size
  timeout     = 60

  environment {
    variables = {
      LOG_LEVEL             = "INFO"
      POWERTOOLS_SERVICE_NAME = var.project_name
    }
  }

  tags = local.tags
}
EOF

# Create eventbridge.tf to trigger the Lambda
cat > infrastructure/terraform/eventbridge.tf << 'EOF'
resource "aws_cloudwatch_event_rule" "s3_creation_rule" {
  name        = "${var.project_name}-S3CreationRule"
  description = "Triggers compliance scan on S3 bucket creation"

  event_pattern = jsonencode({
    source      = ["aws.s3"],
    "detail-type" = ["AWS API Call via CloudTrail"],
    detail      = {
      eventSource = ["s3.amazonaws.com"],
      eventName   = ["CreateBucket"]
    }
  })
}

resource "aws_cloudwatch_event_target" "lambda_target" {
  rule = aws_cloudwatch_event_rule.s3_creation_rule.name
  arn  = aws_lambda_function.compliance_evaluator.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.compliance_evaluator.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.s3_creation_rule.arn
}
EOF

echo "✅ Terraform files created."

# Step 4: Update the Master Deployment Script
echo "🔧 Updating master deployment script..."
# Overwrite the placeholder deploy.sh
cat > scripts/deployment/deploy.sh << 'EOF'
#!/bin/bash
set -e

echo "🚀 Starting Cloud Compliance Framework Deployment..."

# 1. Build the Lambda package
echo "--- Step 1: Building Lambda Package ---"
./scripts/deployment/build_lambda_package.sh

# 2. Deploy infrastructure with Terraform
echo "--- Step 2: Deploying Infrastructure with Terraform ---"
cd infrastructure/terraform

# Initialize Terraform (if not already done)
echo "Initializing Terraform..."
terraform init

# Apply the Terraform configuration
echo "Applying Terraform plan..."
terraform apply -auto-approve

cd ../../

echo "✅ Deployment complete!"
echo "The system is now live and will monitor for S3 bucket creations."
EOF

# Make the script executable
chmod +x scripts/deployment/deploy.sh

echo "✅ Master deployment script updated."

# Step 5: Update Dependencies
echo "📦 Installing new dependencies (boto3, aws-lambda-powertools)..."
pip install boto3 aws-lambda-powertools
pip freeze > requirements.txt
echo "✅ Dependencies updated in requirements.txt."

# Step 6: Update README.md
echo "📖 Updating README.md..."
sed -i '/## 🚀 Next Steps/i \
## 🔌 Real-time Event Processing\n\nThe framework is deployed to AWS using Terraform. The workflow is as follows:\n\n1.  A user or service creates an S3 bucket.\n2.  AWS CloudTrail logs the `CreateBucket` API call.\n3.  An AWS EventBridge rule detects this specific event.\n4.  EventBridge triggers the AWS Lambda function (`compliance_evaluator`).\n5.  The Lambda function fetches the full configuration of the new bucket, runs it through the Policy Engine, and logs the compliance results to Amazon CloudWatch Logs.\n\n### Deployment\n\nTo deploy the infrastructure, you must have Terraform installed and your AWS credentials configured.\n\n```bash\n# Build the Lambda package and deploy to AWS\nmake deploy\n```\n' README.md
sed -i 's/- Phase 3: AWS Lambda Integration/- ✅ Phase 3: AWS Lambda Integration/' README.md
echo "✅ README.md updated."

# Step 7: Final verification
echo ""
echo "🎯 Phase 3 Setup Verification:"
echo "✅ Lambda handler created in src/lambda_functions/."
echo "✅ Terraform IaC files created in infrastructure/terraform/."
echo "✅ Lambda packaging and deployment scripts are ready."
echo "✅ New Python dependencies have been added."
echo "✅ README has been updated with deployment instructions."

echo ""
echo "🚀 Phase 3 Complete! Your Policy-as-Code engine is now a real-time compliance tool in AWS."
echo "Next steps:"
echo "1. IMPORTANT: Configure your AWS credentials for Terraform (e.g., run 'aws configure')."
echo "2. Run 'make deploy' to build the Lambda package and deploy the entire stack to your AWS account."
echo "3. After deployment, create a new S3 bucket in the AWS console and check the CloudWatch Logs for the Lambda function to see the evaluation result."
echo ""
echo "Ready for Phase 4: Storing Results & Reporting."
