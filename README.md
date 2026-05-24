# seed-jobs

Job DSL repository that generates all Jenkins folder structures, team build jobs, and platform-controlled CD pipelines from YAML configuration files. Editing YAML files and pushing to `main` is the only supported way to add or modify jobs.

---

## What it does

The master seed pipeline (`pipelines/MasterSeedPipeline.groovy`) runs every 5 minutes. It:

1. Validates every `teams/*.yml` against `clouds/cloud-registry.yml`.
2. Generates Job DSL for team folders, repositories, and build jobs.
3. Generates Job DSL for platform-controlled folders: `platform/bakery`, `platform/infra`, `platform/services`, `platform/compliance`.
4. Calls `jobDsl` with `removedJobAction: DELETE` -- jobs removed from YAML are deleted from Jenkins.

---

## Bootstrapping Jenkins (first run)

1. Ensure the Job DSL plugin is installed.
2. In **Manage Jenkins > Configure System > Global Pipeline Libraries**, add `jenkins-library` pointing at this repo's companion library (see `jenkins-library/README.md`).
3. Create a pipeline job named `seed/master-seed` manually (or via JCasC) using `jobs/master_seed.groovy` as the Job DSL script:
   - Source: this repo at `https://github.com/pboyd-oss/seed-jobs.git`, branch `main`.
   - Script path: `pipelines/MasterSeedPipeline.groovy`.
   - Trigger: `H/5 * * * *` (SCM poll).
4. Run `seed/master-seed` once. It will create all other jobs.

After bootstrap, never create or edit jobs in Jenkins directly -- they will be overwritten or deleted on the next seed run.

---

## YAML schema

### `teams/<slug>.yml`

Defines a team's folder, members, repositories, and target environments.

```yaml
team:
  name: "Team Alpha"          # Human-readable display name (required)
  slug: team-a                # Short identifier, must be unique, used in folder paths (required)
  build_cloud: build-shared   # Cloud name from cloud-registry.yml where builds run (required)

  members:                    # At least one member required
    - username: jdoe
      role: admin             # admin: full folder access + Configure; developer: read+build+cancel only
    - username: jsmith
      role: developer

  repositories:               # At least one repository required
    - name: auth-api          # Folder name in Jenkins (required)
      url: https://github.com/org/auth-api.git   # Git remote URL (required)
      coverage_threshold: 80  # Optional: sets TUXGRID_COVERAGE_THRESHOLD on the repo folder
      jobs:                   # At least one job required
        - name: build
          type: multibranch   # 'multibranch' or 'pipeline' (required)
          jenkinsfile: Jenkinsfile   # Relative path to pipeline script in the repo (default: Jenkinsfile)
        - name: release
          type: pipeline
          branch: main        # Required for type: pipeline
          jenkinsfile: Jenkinsfile.release
          cron: "H 2 * * *"  # Optional: adds a cron trigger (omit for SCM poll)

  environments:               # Optional: list of deploy targets
    - name: dev               # Environment name, used in TUXGRID_ENV_<NAME>_* vars
      cloud: build-shared     # Cloud name from cloud-registry.yml
    - name: staging
      cloud: deploy-staging
      namespace: team-a-staging   # Kubernetes namespace for this environment
    - name: production-eu
      cloud: deploy-prod-eu
      namespace: team-a-prod
    - name: aws-prod          # AWS environments use type: aws
      type: aws
      role_arn: arn:aws:iam::111111111111:role/platform-deploy-team-a-prod
```

**Validation rules** (enforced by `validateTeam` in MasterSeedPipeline):
- `slug`, `name`, `build_cloud`, `members`, `repositories` are all required.
- `build_cloud` must exist in `cloud-registry.yml` and the team slug must be in its `allowed_teams` list.
- Each environment's `cloud` must exist in `cloud-registry.yml` and allow this team.
- Each job `type` must be `pipeline` or `multibranch`; pipeline jobs require `branch`.

### `clouds/cloud-registry.yml`

Defines available build and deploy infrastructure. Referenced by team YAML files.

```yaml
clouds:
  - name: build-shared        # Unique identifier, referenced by team.build_cloud
    type: kubernetes           # Currently always 'kubernetes'
    server: https://k8s-build.tuxgrid.com   # Kubernetes API endpoint
    credentials_id: kubeconfig-build-shared  # Jenkins credential ID for kubeconfig
    purpose: build             # 'build' or 'deploy'
    allowed_teams:             # List of team slugs permitted to use this cloud
      - team-a
      - team-b
    registry:                  # Image registry available on this cloud (build clouds only)
      url: gitea.tuxgrid.com
      credentials_id: shared-registry
    pod_templates:             # Pod template specs (build clouds only)
      - name: base
        service_account: jenkins-agent
        containers:
          - name: skaffold
            image: gitea.tuxgrid.com/platform/jenkins-agent-skaffold:latest
            command: cat
            tty: true
            resources:
              requests: { cpu: "500m", memory: "1Gi" }
              limits:   { cpu: "2",    memory: "4Gi" }
```

### `platform/bakery/<name>.yml`

Creates a `platform/bakery/<name>` folder and a `platform/bakery/<name>/build` pipeline job that builds a platform base image.

```yaml
bakery:
  name: base                  # Subfolder name and job display name (required)
  description: "..."          # Human-readable description
  git_url: https://github.com/org/platform-base.git   # Git URL of Dockerfile repo
  env_versions:               # Optional: list of tool keys from config/platform-versions.yaml
    - cosign                  # Injects COSIGN_VERSION env var from platform-versions.yaml
    - skaffold
```

### `platform/services/<slug>.yml`

Creates a full platform service pipeline suite: build, scan, deploy, release, pipeline, source-scan, and attest jobs.

```yaml
service:
  slug: audit-service         # Unique slug; used in folder path platform/services/<slug>
  name: audit-service         # Display name
  desc: "..."                 # Human-readable description
  git_url: https://github.com/org/platform-audit-service.git
  workload: platform-audit-service   # Kubernetes Deployment/DaemonSet name for rollout watch
  namespace: platform         # Kubernetes namespace
  kind: deployment            # 'deployment', 'daemonset', or 'statefulset'
  jenkinsfile: Jenkinsfile    # Optional override (default: Jenkinsfile)
```

### `platform/compliance/<name>.yml`

Creates a compliance scan pipeline in the `platform/` folder.

```yaml
compliance:
  name: audit-compliance      # Job path fragment: platform/<name>
  description: "..."
  script_path: pipelines/PlatformAuditCompliancePipeline.groovy
  trigger: cron               # 'cron' or 'scm'
  cron_spec: "H 6 * * *"     # Required when trigger: cron
  auth: admin_only            # 'admin_only' restricts to admin/jenkins-operator; omit for platform-wide access
  log_keep: 90                # Number of builds to retain
  params:                     # Optional: list of string parameters
    - name: MY_PARAM
      default: ""
      description: "..."
```

### `platform/infra/<name>.yml`

Creates a multibranch pipeline for Terraform GitOps under `platform/infra/<name>`.

```yaml
infra:
  name: terraform             # Subfolder name
  description: "..."
  repo_owner: pboyd-oss       # GitHub org or user
  repository: infra-terraform # GitHub repository name
  credentials: github-token   # Jenkins credential ID for GitHub access
```

### `config/platform-versions.yaml`

Central source of truth for tool versions injected into bakery pipeline jobs.

```yaml
tools:
  cosign:    "v2.5.2"
  skaffold:  "v2.15.0"
  k8s_tools: "1.35.3"
  terraform: "1.9.0"
  # ...
```

Referenced by bakery YAML files via the `env_versions` key. The seed pipeline reads this file and injects `<KEY>_VERSION` environment variables into bakery build jobs.

---

## Pipeline types and their stages

### Team build jobs

Generated for each entry in `repositories[].jobs`. Two types:

- **multibranch**: Discovers branches/PRs automatically. Polls every 5 minutes. Runs the repo's own `Jenkinsfile`.
- **pipeline**: Single-branch job. Polls SCM every 5 minutes or on a cron schedule if `cron` is set.

Team Jenkinsfiles call steps from `jenkins-library`. The platform does not control the content of team Jenkinsfiles.

### Platform release pipeline (`platform/<team>/release`)

Stages: Fetch -> Attest Check -> Extract Predicate -> Cedar Gate -> Pull and Verify -> Sign -> Deploy

Prerequisites: the upstream build must have `tests/v1`, `build/v1`, `pipeline/v1`, and `slsaprovenance1` attestations on its image. The scan pipeline must have run with the target `ENVIRONMENT` to produce a `scan/v1` attestation.

Triggered by: team members or `jenkins-operator`.

### Platform scan pipeline (`platform/<team>/scan` and `platform/services/<slug>/scan`)

Stages: Fetch -> Verify -> Trivy Image -> Trivy Repo -> Checkov -> Render -> Checkov Rendered -> Terraform Plan -> Checkov Plan -> Push Artifacts -> SBOM -> Attest

Produces a `scan/v1` attestation that includes scan results, pre-rendered Kubernetes manifests or Terraform plan (when `ENVIRONMENT` is set), and an SBOM.

### Platform deploy pipeline (`platform/services/<slug>/deploy`)

For platform services only (not team repos). Verifies cosign signature and `slsaprovenance1` before applying via skaffold. Does not require `scan/v1`.

### Platform service pipeline (`platform/services/<slug>/pipeline`)

Orchestrates build -> scan -> deploy -> release for a platform service. Each stage is individually selectable via `RUN_*` parameters.

### Attestation pipeline (`platform/<team>/attest` and `platform/services/<slug>/attest`)

Triggered exclusively by the Jenkins RunListener after a successful build. Reads JUnit results from Jenkins' internal records and creates `tests/v1`, `build/v1`, and `pipeline/v1` attestations. Team members cannot trigger this job.

### Source scan pipeline (`platform/<team>/<repo>/source-scan`)

Triggered by the attest listener. Runs Trivy secrets scan, tfsec, and Checkov against the exact commit SHA from the build. The attest listener checks this passed before scheduling attestation.

### Audit compliance pipeline (`platform/audit-compliance`)

Runs daily. Calls Cedar `AuditCompliance` for every team pipeline and reports gaps where attestations are missing or stale. Marks the build `UNSTABLE` on findings.

### Policy scan pipeline (`platform/policy-scan`)

Scans the platform's own infrastructure code (Terraform, Kubernetes manifests, Dockerfiles) with Trivy + Checkov + tfsec + Infracost. Triggered by changes to the platform infra repo.

---

## How to add a new team

1. Create `teams/<new-slug>.yml` following the schema above.
2. Ensure the `build_cloud` value exists in `clouds/cloud-registry.yml` and the slug is in `allowed_teams`.
3. For each environment, ensure the target cloud exists and lists the slug in `allowed_teams`.
4. Commit and push to `main`. The master seed will pick up the change within 5 minutes.

The seed will create:
- `teams/<slug>/` folder with member permissions and environment variables
- `teams/<slug>/<repo>/<job>` for each repository job
- `platform/<slug>/` folder
- `platform/<slug>/release`, `platform/<slug>/scan`, `platform/<slug>/attest` platform-controlled jobs
- `platform/<slug>/<repo>/source-scan` for each repository

---

## Folder and job path reference

| Path pattern | Contents |
|---|---|
| `teams/<slug>/` | Team workspace folder; member permissions scoped here |
| `teams/<slug>/<repo>/<job>` | Team-owned build jobs (Jenkinsfile from team's repo) |
| `platform/<slug>/` | Platform-controlled CD folder for a team |
| `platform/<slug>/release` | Full release gate (scan/v1 + Cedar + deploy) |
| `platform/<slug>/scan` | Image + source scan + SBOM |
| `platform/<slug>/attest` | Build attestation (triggered by RunListener only) |
| `platform/<slug>/<repo>/source-scan` | Per-repo source scan at pinned commit |
| `platform/bakery/<name>/build` | Platform base image build |
| `platform/infra/<name>` | Multibranch Terraform GitOps |
| `platform/services/<slug>/` | Platform service pipeline suite |
| `platform/services/<slug>/pipeline` | Chained build->scan->deploy->release wrapper |
| `platform/audit-compliance` | Daily attestation gap report |
| `platform/policy-scan` | Platform infra security scan |
| `seed/master-seed` | The seed pipeline itself |

---

## Required Jenkins credentials

| Credential ID | Type | Used by |
|---|---|---|
| `harbor-robot-platform` | Username/Password | All build, sign, scan, and deploy pipelines |
| `cosign-key` | Secret text | Sign and attest pipelines |
| `cosign-public-key` | Secret text | Verify steps in scan and deploy pipelines |
| `git-deploy-key` | SSH key | Source checkout in scan and deploy pipelines |
| `github-token` | Username/Password or token | Infra multibranch pipeline |
| `infracost-api-key` | Secret text | PlatformPolicyScanPipeline Infracost stage |
| `kubeconfig-<cloud>` | File | One per cloud entry in cloud-registry.yml for deploy pipelines |
