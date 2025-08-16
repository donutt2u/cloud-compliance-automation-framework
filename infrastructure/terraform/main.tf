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
