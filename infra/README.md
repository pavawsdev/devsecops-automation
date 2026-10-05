# infra — one Terraform codebase, three environments

## Layout

```
infra/
├── versions.tf / providers.tf   # partial S3 backend, allowed_account_ids guard
├── variables.tf                 # every env difference is a variable / feature flag
├── guardrails.tf                # minimum baseline per env, enforced at plan time
├── main.tf                      # baseline: all envs
├── access_logging.tf            # enable_access_logging      (stage, prod)
├── dr_replication.tf            # enable_dr_replication      (prod)
├── security_alerting.tf         # enable_security_alerting   (prod)
├── tests/environments.tftest.hcl
└── envs/
    ├── dev/   terraform.tfvars  backend.hcl  checkov.yaml
    ├── stage/ terraform.tfvars  backend.hcl  checkov.yaml
    └── prod/  terraform.tfvars  backend.hcl  checkov.yaml
```

| | dev | stage | prod |
|---|---|---|---|
| Encryption | AWS-managed key | dedicated KMS key, rotated | dedicated KMS key, rotated |
| Versioning | off | on | on |
| Access logging | off | on | on |
| DR replica (other region) | – | – | yes |
| Tamper alerting (EventBridge → SNS) | – | – | yes |
| Retention | 14 days | 90 days | 400 days |
| Resources | 7 | 18 | 33 |

## How environments are kept apart

1. **Code is shared and configuration is per environment.** Resources read feature flags
   (`count = var.enable_x ? 1 : 0`) and never check `environment == "prod"`. Adding something
   that only prod gets means a new flag that defaults to off in dev and stage.
2. **Each environment has its own state** (`envs/<env>/backend.hcl`), ideally in its own AWS
   account. A plan for one environment cannot read or change another environment's resources.
3. **Credentials only work in one account.** Each environment has its own OIDC roles, and
   `allowed_account_ids` makes Terraform refuse to run against the wrong account.
4. **Guardrails.** `guardrails.tf` makes the plan fail if a tfvars edit turns off a stage or
   prod control. `terraform test` checks which resources each environment gets.
5. **Every PR plans all three environments.** A change meant only for prod should show
   *No changes* for dev and stage. If it doesn't, you see that before merging.
6. **Promotion.** The same commit goes dev → stage → prod. Each apply runs exactly the plan
   that was reviewed, and Terraform rejects it if the state changed after the plan was made.
7. **Policy scans run per environment.** Checkov scans each environment's plan JSON, using
   that environment's `checkov.yaml` as its list of accepted risks. Prod's list is empty.

## Day-to-day flow

1. Create a branch and edit Terraform or `envs/<env>/terraform.tfvars`.
2. Run `terraform fmt -recursive && terraform validate && terraform test` locally.
3. Open a PR. CI runs the static checks and plans dev, stage and prod. The plans appear in
   the job summary.
4. Code owners review. Prod tfvars, guardrails, accepted-risk files and workflows also need
   security-team approval.
5. Merge. Dev applies automatically, then stage, then prod, each after approval in its
   GitHub Environment. An environment whose plan has no changes is skipped, so it asks for
   no approval.
6. A nightly run plans every environment and fails if the real infrastructure has drifted
   from `main`.

## One-time setup (per environment)

- **State bucket** `tfstate-devsecops-<env>`: versioned, encrypted, public access blocked.
  Locking uses S3 native lock files (`use_lockfile`), so no DynamoDB table is needed.
- **GitHub OIDC provider** in each AWS account, plus two IAM roles:
  - *plan role* (read-only, plus read access to the state bucket). Trust condition
    `token.actions.githubusercontent.com:sub` = `repo:<org>/<repo>:pull_request` or
    `repo:<org>/<repo>:ref:refs/heads/main`.
  - *apply role* (write). Trust condition `sub` = `repo:<org>/<repo>:environment:<env>`, so
    only a job running in that approved GitHub Environment can assume it.
- **Repository variables**: `TF_PLAN_ROLE_ARN_DEV`, `TF_PLAN_ROLE_ARN_STAGE`, `TF_PLAN_ROLE_ARN_PROD`.
- **GitHub Environments** `dev`, `stage`, `prod`, each with an environment variable
  `TF_APPLY_ROLE_ARN`, deployment branches limited to `main`, and required reviewers on
  stage and prod (prod: prevent self-review).
- **Branch protection on `main`**: PR required, code-owner review, and the `infra` checks
  must pass.
- Replace the `TODO` account IDs, state bucket names and CODEOWNERS teams.

## Running locally

```bash
terraform init -backend-config=envs/dev/backend.hcl
terraform plan -var-file=envs/dev/terraform.tfvars
```
Always pass the matching `backend.hcl` and `terraform.tfvars` pair. In shared environments,
apply only through the pipeline.
