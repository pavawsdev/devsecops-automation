terraform {
  required_version = ">= 1.10.0" # S3 native state locking (use_lockfile)

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.80"
    }
  }

  # Partial configuration: bucket/key/region come from envs/<env>/backend.hcl,
  # so every environment has its own state file and a plan can never touch another env.
  backend "s3" {}
}
