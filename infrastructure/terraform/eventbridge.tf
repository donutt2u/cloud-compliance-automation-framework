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
