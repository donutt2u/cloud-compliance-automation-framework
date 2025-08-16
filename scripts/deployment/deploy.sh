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
