# State for prod only. Lives in the prod account, so prod credentials cannot read other envs' state.
bucket       = "tfstate-devsecops-prod" # TODO: pre-created, versioned, encrypted state bucket
key          = "devsecops-automation/infra.tfstate"
region       = "us-east-1"
encrypt      = true
use_lockfile = true
