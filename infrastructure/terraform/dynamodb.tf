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
