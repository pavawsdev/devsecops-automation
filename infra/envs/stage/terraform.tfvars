# Stage: production-like security controls, without prod's DR and alerting.
environment = "stage"
account_id  = "222222222222" # TODO: stage AWS account

report_retention_days             = 90
noncurrent_version_retention_days = 14

enable_versioning        = true
use_customer_managed_key = true
enable_access_logging    = true
enable_dr_replication    = false
enable_security_alerting = false
