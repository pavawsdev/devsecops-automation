# Every environment difference is a variable set in envs/<env>/terraform.tfvars.
# Resources never test `var.environment == "prod"` directly; they read a feature flag,
# and guardrails.tf enforces which flags each environment is allowed to turn off.

variable "environment" {
  type        = string
  description = "Deployment environment."
  validation {
    condition     = contains(["dev", "stage", "prod"], var.environment)
    error_message = "environment must be one of dev, stage, prod."
  }
}

variable "account_id" {
  type        = string
  description = "AWS account this environment lives in (one account per environment)."
  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be a 12-digit AWS account id."
  }
}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "dr_region" {
  type    = string
  default = "us-west-2"
}

variable "bucket_prefix" {
  type    = string
  default = "secops-vuln-reports"
}

variable "extra_tags" {
  type    = map(string)
  default = {}
}

# ---- sizing / cost -------------------------------------------------------------

variable "report_retention_days" {
  type        = number
  description = "Days to keep current report objects."
  validation {
    condition     = var.report_retention_days >= 1 && var.report_retention_days <= 3650
    error_message = "report_retention_days must be between 1 and 3650."
  }
}

variable "noncurrent_version_retention_days" {
  type        = number
  default     = 30
  description = "Days to keep superseded object versions (only when versioning is on)."
}

variable "kms_deletion_window_days" {
  type    = number
  default = 30
  validation {
    condition     = var.kms_deletion_window_days >= 7 && var.kms_deletion_window_days <= 30
    error_message = "kms_deletion_window_days must be between 7 and 30."
  }
}

# ---- feature flags -------------------------------------------------------------

variable "enable_versioning" {
  type        = bool
  description = "Keep previous versions of report objects."
}

variable "use_customer_managed_key" {
  type        = bool
  description = "Encrypt with a dedicated, rotated KMS key instead of the AWS-managed S3 key."
}

variable "enable_access_logging" {
  type        = bool
  description = "Stage+: S3 server access logs to a dedicated log bucket."
}

variable "enable_dr_replication" {
  type        = bool
  description = "Prod: replicate reports to a bucket in var.dr_region."
}

variable "enable_security_alerting" {
  type        = bool
  description = "Prod: alert on bucket policy / encryption / public-access changes."
}

variable "alert_email" {
  type        = string
  default     = null
  description = "Optional e-mail subscribed to security alerts (needs manual confirmation)."
}
