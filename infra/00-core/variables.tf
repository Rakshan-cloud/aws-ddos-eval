variable "region" {
  description = "Region for regional resources. The CloudFront web ACL lives in us-east-1 regardless (decision D2)."
  type        = string
  default     = "eu-west-1"
}

variable "name_prefix" {
  description = "Prefix on every resource name, so the whole study is identifiable in the console and in Cost Explorer."
  type        = string
  default     = "ddos-eval"
}

variable "stage_name" {
  description = "API Gateway stage name. Fixed for the whole study: it appears in every metric dimension and log stream."
  type        = string
  default     = "exp"
}

variable "lambda_memory_mb" {
  description = "Lambda memory. A controlled variable - changing it mid-study invalidates every completed run."
  type        = number
  default     = 128
}

variable "lambda_timeout_s" {
  description = "Lambda timeout. Generous relative to the workload; the function does no I/O."
  type        = number
  default     = 10
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention. Outlives the project, but bounds storage cost."
  type        = number
  default     = 30
}
