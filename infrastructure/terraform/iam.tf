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
      {
        # Permissions to write evaluation results to DynamoDB
        Action   = [
          "dynamodb:PutItem",
          "dynamodb:UpdateItem"
        ],
        Effect   = "Allow",
        Resource = aws_dynamodb_table.results_table.arn
      },
      {
        # Permissions to remediate S3 bucket configurations
        Action   = [
          "s3:PutBucketVersioning"
        ],
        Effect   = "Allow",
        # Be specific to avoid overly broad permissions
        Resource = "arn:aws:s3:::*"
      },
      # Add more read-only permissions for other services here
      # e.g., "ec2:DescribeInstances", "iam:GetRole", etc.
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_policy_attach" {
  role       = aws_iam_role.lambda_exec_role.name
  policy_arn = aws_iam_policy.lambda_policy.arn
}
