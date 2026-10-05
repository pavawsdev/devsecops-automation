# State for stage only. Lives in the stage account, so stage credentials cannot read other envs' state.
bucket       = "tfstate-devsecops-stage" # TODO: pre-created, versioned, encrypted state bucket
key          = "devsecops-automation/infra.tfstate"
region       = "us-east-1"
encrypt      = true
use_lockfile = true
