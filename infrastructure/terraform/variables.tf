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
variable "enable_remediation" {
  description = "Safety switch to enable/disable auto-remediation. Set to true to enable."
  type        = bool
  default     = false
}
  description = "The amount of memory to allocate to the Lambda function."
  type        = number
  default     = 256
}
