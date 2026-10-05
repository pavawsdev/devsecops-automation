output "reports_bucket" {
  value = aws_s3_bucket.reports.id
}

output "reports_kms_key_arn" {
  value = one(aws_kms_key.reports[*].arn)
}

output "access_logs_bucket" {
  value = one(aws_s3_bucket.access_logs[*].id)
}

output "replica_bucket" {
  value = one(aws_s3_bucket.replica[*].id)
}

output "security_alerts_topic_arn" {
  value = one(aws_sns_topic.security_alerts[*].arn)
}
