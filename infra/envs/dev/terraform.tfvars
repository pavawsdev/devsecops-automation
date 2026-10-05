# Dev: cheapest configuration that still meets the always-on baseline
# (encryption, public access block, TLS-only policy, lifecycle).
environment = "dev"
account_id  = "111111111111" # TODO: dev AWS account

report_retention_days    = 14
kms_deletion_window_days = 7

enable_versioning        = false
use_customer_managed_key = false # AWS-managed aws/s3 key, no KMS key charge
enable_access_logging    = false
enable_dr_replication    = false
enable_security_alerting = false
