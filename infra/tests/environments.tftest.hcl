# Plans each environment's tfvars against a mocked AWS provider (no credentials needed)
# and asserts what each environment gets. Run: terraform test

mock_provider "aws" {
  mock_data "aws_iam_policy_document" {
    defaults = { json = "{}" }
  }
}

mock_provider "aws" {
  alias = "dr"
}

run "dev_is_minimal" {
  command = plan
  variables {
    environment              = "dev"
    account_id               = "111111111111"
    report_retention_days    = 14
    enable_versioning        = false
    use_customer_managed_key = false
    enable_access_logging    = false
    enable_dr_replication    = false
    enable_security_alerting = false
  }
  assert {
    condition     = length(aws_kms_key.reports) == 0 && length(aws_s3_bucket_versioning.reports) == 0
    error_message = "dev should use the AWS-managed key and no versioning"
  }
  assert {
    condition     = length(aws_s3_bucket.access_logs) + length(aws_s3_bucket.replica) + length(aws_sns_topic.security_alerts) == 0
    error_message = "dev must not create stage/prod-only resources"
  }
}

run "stage_adds_security_controls" {
  command = plan
  variables {
    environment              = "stage"
    account_id               = "222222222222"
    report_retention_days    = 90
    enable_versioning        = true
    use_customer_managed_key = true
    enable_access_logging    = true
    enable_dr_replication    = false
    enable_security_alerting = false
  }
  assert {
    condition     = length(aws_kms_key.reports) == 1 && length(aws_s3_bucket_logging.reports) == 1
    error_message = "stage needs a CMK and access logging"
  }
  assert {
    condition     = length(aws_s3_bucket.replica) + length(aws_sns_topic.security_alerts) == 0
    error_message = "stage must not create prod-only resources"
  }
}

run "prod_has_everything" {
  command = plan
  variables {
    environment              = "prod"
    account_id               = "333333333333"
    report_retention_days    = 400
    enable_versioning        = true
    use_customer_managed_key = true
    enable_access_logging    = true
    enable_dr_replication    = true
    enable_security_alerting = true
  }
  assert {
    condition     = length(aws_s3_bucket_replication_configuration.reports) == 1
    error_message = "prod needs DR replication"
  }
  assert {
    condition     = length(aws_cloudwatch_event_rule.bucket_tampering) == 1
    error_message = "prod needs tamper alerting"
  }
}

run "prod_cannot_disable_dr" {
  command = plan
  variables {
    environment              = "prod"
    account_id               = "333333333333"
    report_retention_days    = 400
    enable_versioning        = true
    use_customer_managed_key = true
    enable_access_logging    = true
    enable_dr_replication    = false
    enable_security_alerting = true
  }
  expect_failures = [terraform_data.guardrails]
}

run "stage_cannot_drop_baseline" {
  command = plan
  variables {
    environment              = "stage"
    account_id               = "222222222222"
    report_retention_days    = 90
    enable_versioning        = true
    use_customer_managed_key = false
    enable_access_logging    = true
    enable_dr_replication    = false
    enable_security_alerting = false
  }
  expect_failures = [terraform_data.guardrails]
}

run "prod_short_retention_rejected" {
  command = plan
  variables {
    environment              = "prod"
    account_id               = "333333333333"
    report_retention_days    = 30
    enable_versioning        = true
    use_customer_managed_key = true
    enable_access_logging    = true
    enable_dr_replication    = true
    enable_security_alerting = true
  }
  expect_failures = [terraform_data.guardrails]
}
