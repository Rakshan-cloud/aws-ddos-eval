terraform {
  required_version = "~> 1.16"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
  backend "local" {
    path = "terraform.tfstate"
  }
}

provider "aws" {
  region = "us-east-1"

  default_tags {
    tags = {
      project       = "ddos-eval"
      managedby     = "terraform"
      component     = "30-waf-rate"
      configuration = "C4"
    }
  }
}

variable "name_prefix" {
  type    = string
  default = "ddos-eval"
}

variable "log_retention_days" {
  type    = number
  default = 30
}

variable "rate_limit" {
  description = <<-EOT
    Requests per evaluation window per source IP before the rule blocks.

    100 per 60s is chosen so the threshold sits in the gap between the
    scenarios (see docs/design-freeze.md):
       legitimate client   1 req/s =  60 per window  -> below
       S4 signature        1 req/s =  60 per window  -> below, isolates content
       S3 sustained        5 req/s = 300 per window  -> above, isolates rate
       S2 burst           10 req/s = 600 per window  -> above, isolates rate

    AWS's lowest permitted setting is 10.

    FROZEN for the whole study. Changing it resets AWS's internal counters and
    invalidates every completed C4 run.
  EOT
  type        = number
  default     = 100

  validation {
    condition     = var.rate_limit >= 10
    error_message = "AWS WAF does not permit a rate limit below 10 per evaluation window."
  }
}

variable "evaluation_window_sec" {
  description = "Valid values are 60, 120, 300 and 600. AWS default is 300; 60 is used here to shorten detection onset and keep runs to 600s."
  type        = number
  default     = 60

  validation {
    condition     = contains([60, 120, 300, 600], var.evaluation_window_sec)
    error_message = "AWS WAF permits only 60, 120, 300 or 600 second evaluation windows."
  }
}

locals {
  name = "${var.name_prefix}-rate"
}

# ------------------------------------------------------------------ C4 ------
# Rate-based protection. This rule inspects NOTHING about request content --
# only how many arrive from a source IP per window.
#
# Aggregation is by source IP, which is why the study needs two generator
# hosts with distinct Elastic IPs (decision D3). With one source, blocking the
# attacker would block the legitimate client too and force M2 to zero by
# construction.

resource "aws_wafv2_web_acl" "rate" {
  name  = local.name
  scope = "CLOUDFRONT"

  default_action {
    allow {}
  }

  rule {
    name     = "RateLimitPerIP"
    priority = 1

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit                 = var.rate_limit
        evaluation_window_sec = var.evaluation_window_sec
        aggregate_key_type    = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "RateLimitPerIP"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "ddosEvalRate"
    sampled_requests_enabled   = true
  }
}

resource "aws_cloudwatch_log_group" "waf" {
  name              = "aws-waf-logs-${local.name}"
  retention_in_days = var.log_retention_days
}

resource "aws_wafv2_web_acl_logging_configuration" "rate" {
  resource_arn            = aws_wafv2_web_acl.rate.arn
  log_destination_configs = [aws_cloudwatch_log_group.waf.arn]
}

output "web_acl_arn" {
  value = aws_wafv2_web_acl.rate.arn
}

output "web_acl_name" {
  value = aws_wafv2_web_acl.rate.name
}

output "log_group" {
  value = aws_cloudwatch_log_group.waf.name
}

output "rate_limit" {
  value = var.rate_limit
}

output "evaluation_window_sec" {
  value = var.evaluation_window_sec
}

output "capacity_wcu" {
  value = aws_wafv2_web_acl.rate.capacity
}
