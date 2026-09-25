data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  name = var.name_prefix
}

# ---------------------------------------------------------------- Lambda ----

data "archive_file" "handler" {
  type        = "zip"
  source_file = "${path.module}/lambda_src/handler.py"
  output_path = "${path.module}/.build/handler.zip"
}

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda" {
  name               = "${local.name}-lambda"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

# The function writes logs and does nothing else, so this is the whole policy.
resource "aws_iam_role_policy_attachment" "lambda_logs" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${local.name}-target"
  retention_in_days = var.log_retention_days
}

resource "aws_lambda_function" "target" {
  function_name = "${local.name}-target"
  role          = aws_iam_role.lambda.arn
  handler       = "handler.handler"
  runtime       = "python3.12"
  architectures = ["arm64"]

  filename         = data.archive_file.handler.output_path
  source_code_hash = data.archive_file.handler.output_base64sha256

  memory_size = var.lambda_memory_mb
  timeout     = var.lambda_timeout_s

  # Keep the environment empty. Every variable is one more thing that could
  # differ between runs.
  depends_on = [
    aws_iam_role_policy_attachment.lambda_logs,
    aws_cloudwatch_log_group.lambda,
  ]
}

# ----------------------------------------------------------- API Gateway ----

resource "aws_api_gateway_rest_api" "api" {
  name        = "${local.name}-api"
  description = "System under test: MSc dissertation on AWS-native DDoS mitigation"

  endpoint_configuration {
    types = ["REGIONAL"]
  }
}

# A greedy proxy on the root. Scenario S4 sends payloads in the URI path
# (GenericLFI_URIPATH, EC2MetaDataSSRF_URIPATH), so every path must reach the
# integration rather than being rejected by API Gateway as an unknown route --
# otherwise those payloads would never be evaluated by the WAF at all.
resource "aws_api_gateway_resource" "proxy" {
  rest_api_id = aws_api_gateway_rest_api.api.id
  parent_id   = aws_api_gateway_rest_api.api.root_resource_id
  path_part   = "{proxy+}"
}

resource "aws_api_gateway_method" "proxy" {
  rest_api_id   = aws_api_gateway_rest_api.api.id
  resource_id   = aws_api_gateway_resource.proxy.id
  http_method   = "ANY"
  authorization = "NONE"
}

resource "aws_api_gateway_method" "root" {
  rest_api_id   = aws_api_gateway_rest_api.api.id
  resource_id   = aws_api_gateway_rest_api.api.root_resource_id
  http_method   = "ANY"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "proxy" {
  rest_api_id             = aws_api_gateway_rest_api.api.id
  resource_id             = aws_api_gateway_resource.proxy.id
  http_method             = aws_api_gateway_method.proxy.http_method
  type                    = "AWS_PROXY"
  integration_http_method = "POST"
  uri                     = aws_lambda_function.target.invoke_arn
}

resource "aws_api_gateway_integration" "root" {
  rest_api_id             = aws_api_gateway_rest_api.api.id
  resource_id             = aws_api_gateway_rest_api.api.root_resource_id
  http_method             = aws_api_gateway_method.root.http_method
  type                    = "AWS_PROXY"
  integration_http_method = "POST"
  uri                     = aws_lambda_function.target.invoke_arn
}

resource "aws_lambda_permission" "apigw" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.target.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.api.execution_arn}/*/*"
}

resource "aws_api_gateway_deployment" "this" {
  rest_api_id = aws_api_gateway_rest_api.api.id

  # Redeploy whenever the API shape changes, so a stage never serves a stale
  # definition mid-study.
  triggers = {
    redeploy = sha1(jsonencode([
      aws_api_gateway_resource.proxy.id,
      aws_api_gateway_method.proxy.id,
      aws_api_gateway_method.root.id,
      aws_api_gateway_integration.proxy.id,
      aws_api_gateway_integration.root.id,
    ]))
  }

  lifecycle {
    create_before_destroy = true
  }
}

# ------------------------------------------------------ Logging (T014) ------

resource "aws_cloudwatch_log_group" "apigw_access" {
  name              = "/aws/apigateway/${local.name}-access"
  retention_in_days = var.log_retention_days
}

# API Gateway execution logging is configured per account, not per API. This
# role is what lets API Gateway write to CloudWatch Logs at all.
data "aws_iam_policy_document" "apigw_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["apigateway.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "apigw_cloudwatch" {
  name               = "${local.name}-apigw-cloudwatch"
  assume_role_policy = data.aws_iam_policy_document.apigw_assume.json
}

resource "aws_iam_role_policy_attachment" "apigw_cloudwatch" {
  role       = aws_iam_role.apigw_cloudwatch.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs"
}

resource "aws_api_gateway_account" "this" {
  cloudwatch_role_arn = aws_iam_role.apigw_cloudwatch.arn
  depends_on          = [aws_iam_role_policy_attachment.apigw_cloudwatch]
}

resource "aws_api_gateway_stage" "exp" {
  rest_api_id   = aws_api_gateway_rest_api.api.id
  deployment_id = aws_api_gateway_deployment.this.id
  stage_name    = var.stage_name

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.apigw_access.arn

    # One JSON object per request. requestId and the timing fields are what
    # the client-side records join against when reconciling M3 and M4.
    format = jsonencode({
      requestId          = "$context.requestId"
      requestTime        = "$context.requestTime"
      requestTimeEpoch   = "$context.requestTimeEpoch"
      sourceIp           = "$context.identity.sourceIp"
      userAgent          = "$context.identity.userAgent"
      httpMethod         = "$context.httpMethod"
      path               = "$context.path"
      status             = "$context.status"
      responseLatency    = "$context.responseLatency"
      integrationLatency = "$context.integrationLatency"
      responseLength     = "$context.responseLength"
      domainName         = "$context.domainName"
    })
  }

  depends_on = [aws_api_gateway_account.this]
}

# ----------------------------------- Detailed metrics + throttles (T015) ----

resource "aws_api_gateway_method_settings" "all" {
  rest_api_id = aws_api_gateway_rest_api.api.id
  stage_name  = aws_api_gateway_stage.exp.stage_name
  method_path = "*/*"

  settings {
    # Per-method CloudWatch metrics. Without this, only aggregate stage metrics
    # are published and Latency percentiles cannot be broken down.
    metrics_enabled = true
    logging_level   = "INFO"

    # Log the full request/response so S4 payloads are visible in the execution
    # log for cross-checking against WAF log labels in Week 3.
    data_trace_enabled = true

    # Explicit, recorded throttle settings. API Gateway ALWAYS throttles; these
    # values are set deliberately rather than left to the account default so
    # that the confound in configuration C1 is a known quantity (task T017).
    # Both sit far above the study's 11 req/s ceiling, so they should never
    # engage - which is exactly what the measurements must demonstrate.
    throttling_rate_limit  = 1000
    throttling_burst_limit = 2000
  }
}
