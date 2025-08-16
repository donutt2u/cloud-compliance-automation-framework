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
      ENABLE_REMEDIATION    = var.enable_remediation
      DYNAMODB_TABLE_NAME = aws_dynamodb_table.results_table.name
    }
  }

  tags = local.tags
}
