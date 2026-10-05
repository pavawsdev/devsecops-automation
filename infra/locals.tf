locals {
  name = "${var.bucket_prefix}-${var.environment}-${var.account_id}"

  tags = merge({
    environment         = var.environment
    owner               = "secops"
    managed_by          = "terraform"
    repository          = "devsecops-automation"
    data_classification = "internal"
  }, var.extra_tags)
}
