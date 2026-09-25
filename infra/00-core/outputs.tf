output "api_invoke_url" {
  description = "Direct API Gateway stage URL. This is configuration C1 (unprotected), and the CloudFront origin for C2-C5."
  value       = aws_api_gateway_stage.exp.invoke_url
}

output "rest_api_id" {
  description = "REST API id. Needed to associate a REGIONAL web ACL with the stage, if that path is ever used."
  value       = aws_api_gateway_rest_api.api.id
}

output "stage_arn" {
  description = "Stage ARN, the resource a REGIONAL web ACL would attach to."
  value       = aws_api_gateway_stage.exp.arn
}

output "api_gateway_origin_domain" {
  description = "Origin domain for the CloudFront distribution built in Week 3."
  value       = "${aws_api_gateway_rest_api.api.id}.execute-api.${data.aws_region.current.region}.amazonaws.com"
}

output "api_gateway_origin_path" {
  description = "Origin path for CloudFront. API Gateway serves the stage under this prefix."
  value       = "/${aws_api_gateway_stage.exp.stage_name}"
}

output "lambda_function_name" {
  description = "Used as the CloudWatch metric dimension when collecting Lambda Duration and Errors."
  value       = aws_lambda_function.target.function_name
}

output "log_group_lambda" {
  description = "Lambda execution log group."
  value       = aws_cloudwatch_log_group.lambda.name
}

output "log_group_apigw_access" {
  description = "API Gateway access log group. One JSON record per request."
  value       = aws_cloudwatch_log_group.apigw_access.name
}

output "throttle_rate_limit" {
  description = "Stage throttle rate set explicitly (task T017). Recorded as a confound present in every configuration, including C1."
  value       = one(aws_api_gateway_method_settings.all.settings[*].throttling_rate_limit)
}

output "throttle_burst_limit" {
  description = "Stage throttle burst set explicitly (task T017)."
  value       = one(aws_api_gateway_method_settings.all.settings[*].throttling_burst_limit)
}
