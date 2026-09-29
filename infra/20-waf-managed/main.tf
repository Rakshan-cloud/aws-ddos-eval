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

# CLOUDFRONT-scope web ACLs exist only in us-east-1. This is an AWS constraint,
# not a choice -- see docs/aws-facts.md.
provider "aws" {
  region = "us-east-1"

  default_tags {
    tags = {
      project       = "ddos-eval"
      managedby     = "terraform"
      component     = "20-waf-managed"
      configuration = "C3"
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

locals {
  name = "${var.name_prefix}-managed"
}

# ------------------------------------------------------------------ C3 ------
# Signature-based protection. Every rule in these groups inspects request
# CONTENT -- headers, URI, query arguments, body. None inspects rate.
#
# That is the hypothesis under test: this configuration is predicted to block
# NOTHING in the flood scenarios (S2, S3) and to block most of the
# signature-bearing scenario (S4).

resource "aws_wafv2_web_acl" "managed" {
  name  = local.name
  scope = "CLOUDFRONT"

  default_action {
    allow {}
  }

  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 1
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesCommonRuleSet"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "CommonRuleSet"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 2
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "KnownBadInputs"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "AWSManagedRulesAmazonIpReputationList"
    priority = 3
    override_action {
      none {}
    }
    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesAmazonIpReputationList"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "IpReputation"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "ddosEvalManaged"
    sampled_requests_enabled   = true
  }
}

# Full per-request logging. This is the source of truth for M1 -- sampled
# requests are capped at 100 per rule over 3 hours and have no denominator.
# AWS requires the log group name to begin with "aws-waf-logs-".
resource "aws_cloudwatch_log_group" "waf" {
  name              = "aws-waf-logs-${local.name}"
  retention_in_days = var.log_retention_days
}

resource "aws_wafv2_web_acl_logging_configuration" "managed" {
  resource_arn            = aws_wafv2_web_acl.managed.arn
  log_destination_configs = [aws_cloudwatch_log_group.waf.arn]
}

output "web_acl_arn" {
  value = aws_wafv2_web_acl.managed.arn
}

output "web_acl_name" {
  description = "CloudWatch metric dimension value for AWS/WAFV2."
  value       = aws_wafv2_web_acl.managed.name
}

output "log_group" {
  value = aws_cloudwatch_log_group.waf.name
}

output "capacity_wcu" {
  description = "Total WCU. Determines the request-processing price tier: Tier 1 up to 1500 WCU at $0.60/million."
  value       = aws_wafv2_web_acl.managed.capacity
}
