# Minimum security baseline per environment. A tfvars edit that weakens stage or prod
# fails at plan time instead of silently reaching the environment.

resource "terraform_data" "guardrails" {
  lifecycle {
    precondition {
      condition = var.environment == "dev" || (
        var.enable_versioning && var.use_customer_managed_key && var.enable_access_logging
      )
      error_message = "stage and prod require enable_versioning, use_customer_managed_key and enable_access_logging."
    }
    precondition {
      condition     = var.environment != "prod" || (var.enable_dr_replication && var.enable_security_alerting)
      error_message = "prod requires enable_dr_replication and enable_security_alerting."
    }
    precondition {
      condition     = !var.enable_dr_replication || (var.enable_versioning && var.use_customer_managed_key)
      error_message = "enable_dr_replication needs enable_versioning and use_customer_managed_key."
    }
    precondition {
      condition     = var.environment != "prod" || var.report_retention_days >= 365
      error_message = "prod must keep reports for at least 365 days (audit evidence)."
    }
  }
}
