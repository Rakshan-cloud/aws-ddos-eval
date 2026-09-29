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
      component     = "35-waf-antiddos"
      configuration = "C5"
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

variable "sensitivity" {
  description = "Anti-DDoS sensitivity to apply: LOW, MEDIUM or HIGH."
  type        = string
  default     = "MEDIUM"

  validation {
    condition     = contains(["LOW", "MEDIUM", "HIGH"], var.sensitivity)
    error_message = "Sensitivity must be LOW, MEDIUM or HIGH."
  }
}

variable "challenge_action" {
  description = "ENABLED or DISABLED for the client-side JavaScript challenge. DISABLED for this study - see the rationale in main.tf."
  type        = string
  default     = "DISABLED"

  validation {
    condition     = contains(["ENABLED", "DISABLED"], var.challenge_action)
    error_message = "challenge_action must be ENABLED or DISABLED."
  }
}

variable "challenge_exempt_uri_regex" {
  description = "AWS requires at least one exempt URI regex whenever the challenge is ENABLED. Unused while it is DISABLED."
  type        = string
  default     = "^/never-matches-anything$"
}

locals {
  name = "${var.name_prefix}-antiddos"
}

# ------------------------------------------------------------------ C5 ------
#
#  ############################  COST WARNING  ############################
#  AWSManagedRulesAntiDDoSRuleSet is $20.00/month + $0.15/million requests,
#  twenty times an ordinary managed rule group. It is PRORATED HOURLY, at
#  about $0.0274/hour.
#
#    torn down between run blocks (~4h total)  ->  ~$0.11
#    left deployed for the project (~3 months) ->  ~$60, exceeding the
#                                                  entire project budget
#
#  This layer is applied immediately before the C5 runs and destroyed
#  immediately afterwards. Never leave it deployed overnight. See risk R12.
#  ########################################################################
#
# This is the novelty-bearing configuration: AWS's only managed rule group
# aimed at layer-7 DDoS, and unmeasured in the published literature. Unlike
# C3 and C4 the expected result is genuinely unknown, so no hypothesis is
# stated for it.

resource "aws_wafv2_web_acl" "antiddos" {
  name  = local.name
  scope = "CLOUDFRONT"

  default_action {
    allow {}
  }

  rule {
    name     = "AWSManagedRulesAntiDDoSRuleSet"
    priority = 1

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesAntiDDoSRuleSet"

        managed_rule_group_configs {
          aws_managed_rules_anti_ddos_rule_set {
            sensitivity_to_block = var.sensitivity

            # Client-side challenge DISABLED -- a deliberate scoping decision,
            # not a convenience.
            #
            # The challenge tier serves a JavaScript puzzle that a browser
            # solves silently. Both traffic sources in this study are scripted
            # HTTP clients, by design. With the challenge enabled, the
            # LEGITIMATE client would be challenged too and would fail, driving
            # M2 to zero for reasons that have nothing to do with DDoS
            # detection -- the same class of measurement artefact that the
            # two-source design (D3) exists to avoid.
            #
            # So C5 measures the rule group's DETECTION AND BLOCKING tier.
            # Its challenge tier is out of scope and is stated as a limitation:
            # a scripted harness cannot represent browser challenge-solving on
            # either side of the comparison.
            client_side_action_config {
              challenge {
                usage_of_action = var.challenge_action
                # Required by AWS whenever the challenge is ENABLED.
                exempt_uri_regular_expression {
                  regex_string = var.challenge_exempt_uri_regex
                }
              }
            }
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AntiDDoS"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "ddosEvalAntiDDoS"
    sampled_requests_enabled   = true
  }
}

resource "aws_cloudwatch_log_group" "waf" {
  name              = "aws-waf-logs-${local.name}"
  retention_in_days = var.log_retention_days
}

resource "aws_wafv2_web_acl_logging_configuration" "antiddos" {
  resource_arn            = aws_wafv2_web_acl.antiddos.arn
  log_destination_configs = [aws_cloudwatch_log_group.waf.arn]
}

output "web_acl_arn" {
  value = aws_wafv2_web_acl.antiddos.arn
}

output "web_acl_name" {
  value = aws_wafv2_web_acl.antiddos.name
}

output "log_group" {
  value = aws_cloudwatch_log_group.waf.name
}

output "sensitivity" {
  value = var.sensitivity
}

output "capacity_wcu" {
  value = aws_wafv2_web_acl.antiddos.capacity
}
