# State for dev only. Lives in the dev account, so dev credentials cannot read other envs' state.
bucket       = "tfstate-devsecops-dev" # TODO: pre-created, versioned, encrypted state bucket
key          = "devsecops-automation/infra.tfstate"
region       = "us-east-1"
encrypt      = true
use_lockfile = true
