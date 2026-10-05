# Prod: full baseline plus DR replication and tamper alerting.
# guardrails.tf rejects a plan that turns any of these controls off.
environment = "prod"
account_id  = "333333333333" # TODO: prod AWS account
region      = "us-east-1"
dr_region   = "us-west-2"

report_retention_days             = 400
noncurrent_version_retention_days = 90

enable_versioning        = true
use_customer_managed_key = true
enable_access_logging    = true
enable_dr_replication    = true
enable_security_alerting = true
alert_email              = null # e.g. "secops-oncall@example.com"
