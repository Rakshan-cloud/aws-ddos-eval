variable "region" {
  type    = string
  default = "eu-west-1"
}

variable "name_prefix" {
  type    = string
  default = "ddos-eval"
}

variable "origin_domain" {
  description = "API Gateway execute-api domain, from the 00-core layer."
  type        = string
}

variable "origin_path" {
  description = "Stage prefix, e.g. /exp. CloudFront prepends this to every forwarded request."
  type        = string
}

variable "web_acl_arn" {
  description = <<-EOT
    Web ACL to attach. Empty string means no WAF, which is configuration C2.
    The config switcher sets this per configuration:
      C2 = ""            C3 = managed rules ACL
      C4 = rate-based    C5 = anti-DDoS ACL
  EOT
  type        = string
  default     = ""
}

variable "config_label" {
  description = "Which configuration is currently deployed. Recorded as a tag so Cost Explorer can attribute spend, and so the switcher can verify what is live."
  type        = string
  default     = "C2"
}

# Looked up by name rather than hardcoded. AWS's managed policy IDs are stable
# but pasting one in would violate the repo's no-hardcoded-resource-IDs rule and
# would silently break if AWS ever reissued it.
data "aws_cloudfront_cache_policy" "disabled" {
  name = "Managed-CachingDisabled"
}

# Forward everything the viewer sent except Host, which must stay as the
# origin's own domain or API Gateway rejects the request. Without this the
# query-string payloads in scenario S4 would never reach the origin -- and,
# more importantly, would not appear in the origin's logs for cross-checking.
data "aws_cloudfront_origin_request_policy" "all_viewer" {
  name = "Managed-AllViewerExceptHostHeader"
}

resource "aws_cloudfront_distribution" "this" {
  enabled         = true
  comment         = "${var.name_prefix} - ${var.config_label}"
  http_version    = "http2"
  is_ipv6_enabled = false
  price_class     = "PriceClass_100"

  # Empty string detaches the web ACL, which is exactly how C2 is expressed.
  web_acl_id = var.web_acl_arn

  origin {
    origin_id   = "apigw"
    domain_name = var.origin_domain
    origin_path = var.origin_path

    custom_origin_config {
      origin_protocol_policy = "https-only"
      http_port              = 80
      https_port             = 443
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  default_cache_behavior {
    target_origin_id       = "apigw"
    viewer_protocol_policy = "https-only"

    allowed_methods = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods  = ["GET", "HEAD"]

    # Caching disabled is a CONTROLLED VARIABLE, not a performance choice.
    # With caching on, repeat requests are served at the edge and never reach
    # the origin, so latency and error metrics would describe the cache rather
    # than the protection layer under test.
    cache_policy_id          = data.aws_cloudfront_cache_policy.disabled.id
    origin_request_policy_id = data.aws_cloudfront_origin_request_policy.all_viewer.id

    compress = false
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }

  tags = {
    configuration = var.config_label
  }
}

output "domain_name" {
  description = "CloudFront domain. This is the endpoint for configurations C2 through C5."
  value       = aws_cloudfront_distribution.this.domain_name
}

output "distribution_id" {
  value = aws_cloudfront_distribution.this.id
}

output "distribution_arn" {
  description = "Needed to associate a CLOUDFRONT-scope web ACL."
  value       = aws_cloudfront_distribution.this.arn
}

output "attached_web_acl" {
  description = "Empty means C2 (no WAF)."
  value       = var.web_acl_arn
}

output "config_label" {
  value = var.config_label
}
