provider "aws" {
  region = var.region

  # Refuse to run against the wrong account even if CI hands us the wrong credentials.
  allowed_account_ids = [var.account_id]

  default_tags {
    tags = local.tags
  }
}

# Disaster-recovery region, only used by prod's cross-region replica.
provider "aws" {
  alias               = "dr"
  region              = var.dr_region
  allowed_account_ids = [var.account_id]

  default_tags {
    tags = local.tags
  }
}
