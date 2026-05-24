# CLAUDE.md - seed-jobs

## What this repo is

A Jenkins Job DSL repository. The master seed pipeline reads YAML files, generates Job DSL code as a string, and submits it to Jenkins via the `jobDsl` step. The resulting jobs all reference pipeline Groovy scripts in this same repo.

## File map

```
jobs/
  master_seed.groovy          - Bootstrap script: creates seed/master-seed pipelineJob. Run once via JCasC or manually.

pipelines/
  MasterSeedPipeline.groovy   - The real entry point. Validates team YAML, generates all DSL, calls jobDsl().
  AttestBuildPipeline.groovy  - Creates tests/v1, build/v1, pipeline/v1 attestations. Triggered by RunListener only.
  PlatformAuditCompliancePipeline.groovy - Daily Cedar AuditCompliance scan across all team pipelines.
  PlatformDeployPipeline.groovy - Verify sig + provenance, then skaffold render + kubectl apply. Platform services only.
  PlatformPolicyScanPipeline.groovy - Trivy + Checkov + tfsec + Infracost on platform infra code.
  PlatformReleasePipeline.groovy - Full release gate: attest check + Cedar + artifact verify + deploy. Used by teams.
  PlatformScanPipeline.groovy - Image + source security scan, SBOM, and scan/v1 attestation.
  PlatformServicePipeline.groovy - Wrapper that chains build->scan->deploy->release for platform services.
  PlatformSourceScanPipeline.groovy - Source-only scan (Trivy secrets, tfsec, Checkov) at pinned commit.

teams/
  team-a.yml                  - Team Alpha configuration (Kubernetes deploy targets)
  team-b.yml                  - Team Beta configuration (AWS deploy targets)

platform/
  bakery/                     - Base image build job definitions (one YAML per image)
    backstage.yml
    base.yml
    build-base.yml
    cosign.yml
    deploy-base.yml
    deploy-sec-base.yml
  compliance/                 - Compliance pipeline definitions
    audit-compliance.yml
    policy-scan.yml
  infra/                      - Terraform GitOps pipeline definitions
    terraform.yml
  services/                   - Platform service pipeline suite definitions
    attest-coordinator.yml
    audit-service.yml
    cedar-sidecar.yml
    platform-agent.yml
    platform-agent-frontend.yml
    tetragon-forwarder.yml
    token-service.yml

clouds/
  cloud-registry.yml          - Available Kubernetes clusters and their allowed teams

config/
  platform-versions.yaml      - Canonical tool versions injected into bakery jobs
```

## Where the DSL generator logic lives

All DSL generation lives in `pipelines/MasterSeedPipeline.groovy`. The key functions:

| Function | What it generates |
|---|---|
| `buildTeamDsl(t, envVars)` | `teams/<slug>/` folder + all repository folders and jobs |
| `buildPlatformReleaseDsl(t, envVars)` | `platform/<slug>/` folder + release, scan, attest, source-scan jobs |
| `buildBakeryDsl(bakery, versions)` | `platform/bakery/<name>/` folder + build job |
| `buildInfraDsl(infra)` | `platform/infra/<name>` multibranch pipeline |
| `buildPlatformServiceDsl(svc)` | Full service suite: build, scan, deploy, release, pipeline, source-scan, attest |
| `buildComplianceDsl(comp)` | Compliance pipeline under `platform/<name>` |
| `buildEnvVars(t, buildCloud)` | `TUXGRID_*` env var map that is injected into every team folder and job |
| `validateTeam(team, clouds, path)` | Assertions that fail the seed with a clear message on bad YAML |

DSL is accumulated as a `StringBuilder` (`allDsl`) and submitted in a single `jobDsl()` call. This means all generated jobs are consistent with each other at each run.

## How pipelines reference jenkins-library

`PlatformDeployPipeline.groovy` uses `@Library('jenkins-library') _` and calls `platformDeploy()` directly. The other pipeline files implement their logic inline without the library (they were written before the library was mature).

Convention going forward: new platform pipelines should use the library steps rather than duplicating credential handling and cosign invocations inline.

## Known gaps

### Hardcoded GitHub URLs in pipeline definitions

All generated `pipelineJob` definitions reference `https://github.com/pboyd-oss/seed-jobs.git` as the source for their `scriptPath`. This is hardcoded inside the DSL generator functions in `MasterSeedPipeline.groovy`. Specifically:
- `buildComplianceDsl` (line ~380)
- `buildPlatformReleaseDsl` (lines ~438, ~487, ~529)
- `buildPlatformServiceDsl` (lines ~683, ~716, ~748, ~780, ~810, ~846)

If this repo is forked, moved, or self-hosted on Gitea, these URLs must be updated throughout `MasterSeedPipeline.groovy`. A config constant at the top of the file would be the right fix.

### Attestation type URLs are hardcoded

The platform attestation type URIs (e.g. `https://tuxgrid.com/attestation/scan/v1`) appear in multiple pipeline files. They are not defined as constants anywhere. Files affected:
- `PlatformReleasePipeline.groovy`
- `PlatformScanPipeline.groovy`
- `AttestBuildPipeline.groovy`
- `PlatformAuditCompliancePipeline.groovy`

### cloud-registry.yml is populated but not consumed at pod-template level

`cloud-registry.yml` defines pod templates under each cloud's `pod_templates` key. The master seed pipeline reads the file for validation and env var injection but does NOT yet generate Kubernetes Cloud pod template configuration from it. Pod templates are currently managed separately (likely via JCasC). The YAML schema is fully defined -- implementing the generator is a future task.

### Only two team YAML files exist

`teams/team-a.yml` and `teams/team-b.yml`. Additional teams (team-c, team-d) are referenced in `cloud-registry.yml` `allowed_teams` lists but have no YAML files yet. The seed validates that YAML files exist; missing team files do not cause failures -- they simply mean those teams have no generated jobs.

### Terraform backend bucket is not configurable

`PlatformReleasePipeline.groovy` and `PlatformScanPipeline.groovy` hardcode the Terraform backend key pattern as `<team-slug>/<environment>/terraform.tfstate`. The bucket/region/DynamoDB table is not set here -- it must be configured in the Terraform modules themselves via a `backend.tf` partial config.

### Cedar sidecar URL is hardcoded

`PlatformReleasePipeline.groovy` calls `http://platform-cedar-sidecar.platform.svc.cluster.local/authorize`. This DNS name is not configurable. If the service moves namespaces or the cluster DNS changes, this line must be updated.

### Audit service URL is hardcoded

`PlatformReleasePipeline.groovy::verifyAuditDigest()` calls `http://platform-audit-service.platform.svc.cluster.local:8080/builds/<auditId>/summary`. Same issue as Cedar.

## How to add a new platform service

1. Create `platform/services/<slug>.yml` with the schema documented in README.md.
2. Commit and push to `main`. The master seed generates the full job suite automatically.
3. Ensure the service's Git repo has a `Jenkinsfile` (or the value from `jenkinsfile` in the YAML).

## How to add a new compliance pipeline

1. Create `platform/compliance/<name>.yml`.
2. Add the corresponding pipeline script to `pipelines/`.
3. Reference it in the YAML via `script_path`.
4. Commit and push.

## How to add a new cloud

1. Add an entry to `clouds/cloud-registry.yml`.
2. Add the team slug to `allowed_teams` in the new entry.
3. Add the corresponding `kubeconfig-<name>` credential to Jenkins.
4. Reference the cloud name in a team YAML environment block.

## DSL removedJobAction: DELETE

The `jobDsl` call in `MasterSeedPipeline` uses `removedJobAction: 'DELETE'`. Any job, folder, or view that is no longer represented in the generated DSL is deleted from Jenkins on the next seed run. This means:
- Renaming a team slug renames the folder but the old folder and all its jobs are deleted.
- Removing a repository from a team YAML deletes all jobs in that repository folder.
- There is no "soft delete" or archiving.

Always review what the seed will delete before removing entries from YAML files.
