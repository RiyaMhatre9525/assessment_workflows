# application_hardening

Assesses application security hardening maturity across connected version
control platforms (GitHub, Azure DevOps) and cloud platforms (Azure), using
a 5-level progressive, fail-fast LangGraph state machine aligned to OWASP
ASVS / MASVS levels.

## API usage

```
POST /api/execute/application_hardening
```

```json
{
  "input_data": {
    "assessment_id": "44444444-4444-4444-4444-444444444444",
    "vcs_platform_type": "github",
    "repository": "myorg/myapp",
    "branch": "main",
    "vcs_credentials": {
      "token": "<github-or-ado-pat>"
    },
    "cloud_platform_type": "azure",
    "cloud_resource_scope": "my-resource-group",
    "cloud_credentials": {
      "access_token": "<pre-acquired ARM bearer token>",
      "subscription_id": "<azure-subscription-id>"
    }
  }
}
```

For `vcs_platform_type: "azure_devops"`, `repository` must be in
`organization/project/repository` form and `vcs_credentials` must contain a
Personal Access Token under `token`.

### Response (immediate, async processing)

```json
{
  "workflow": "application_hardening",
  "status": "in_progress",
  "result": null,
  "error": null,
  "timestamp": "2026-07-01T12:00:00.000000"
}
```

## Levels

| Level | Focus Area | Score Range |
|---|---|---|
| 1 | Security Baseline & Input Protection (ASVS L1, output encoding, parametrization) | 0.0–1.0 |
| 2 | Runtime Security & Container Hardening (ASVS L1 reinforced, non-root containers) | 1.0–2.0 |
| 3 | Enhanced Security & HTTP Headers (ASVS L2 @ 75%, security headers) | 2.0–3.0 |
| 4 | Full ASVS Level 2 Compliance (95–100%) | 3.0–4.0 |
| 5 | Advanced Security & ASVS Level 3 (95–100%) | 4.0–5.0 |

Assessment is fail-fast: if a level fails, the workflow stops and returns
the score for the last-attempted level. Levels beyond the halt point are
reported as `NOT_CHECKED` in `level_wise_criteria`.

## Result fields

- `workflow_name`, `maturity_level`, `score`, `score_range`
- `assessment_details` — `{passed_criteria, failed_criteria, reasoning}` for
  the level the assessment concluded at
- `improvement_recommendations` — aggregated across all completed levels,
  each `{gap, action, affected_level, priority}`
- `level_wise_criteria` — full per-criterion breakdown for all 5 levels
  (`PASSED` / `FAILED` for evaluated levels, `NOT_CHECKED` with a skip
  reason for levels not reached)
- `level_breakdown` — compact `{passed, score}` per evaluated level
- `platform.api_call_log` — every VCS + cloud API call made, for debugging

## Credentials reference

| Field | Platform | Required keys |
|---|---|---|
| `vcs_credentials` | `github` | `token` (PAT with `repo` + code search scope) |
| `vcs_credentials` | `azure_devops` | `token` (PAT), `organization` |
| `cloud_credentials` | `azure` | `access_token` (pre-acquired ARM bearer token), `subscription_id` |

Token acquisition for Azure (OAuth client-credentials against Azure AD) is
expected to happen upstream of this workflow — `cloud_credentials.access_token`
must already be a valid ARM bearer token when the request is submitted.

## Connector guide

Two independent connector registries live in `connectors/__init__.py`:

- `VCS_CONNECTOR_REGISTRY` — code-level connectors (`github`, `azure_devops`),
  each collecting framework/encoding-library detection, CSP presence,
  parametrized-query usage, and an ASVS code-side percentage estimate.
- `CLOUD_CONNECTOR_REGISTRY` — infra-level connectors (`azure`), collecting
  container non-root enforcement and HTTP security header configuration,
  plus an ASVS infra-side percentage estimate.

Both families inherit `connectors/base.py::BasePlatformConnector` and
implement `health_check()` + `collect(scope)`. Their outputs are merged into
a single `ApplicationSecurityData(vcs_data, cloud_data)` object that all
level nodes read from.

**To add a new VCS platform:** add one file to `connectors/` implementing
`BasePlatformConnector`, then add one entry to `VCS_CONNECTOR_REGISTRY`.

**To add a new cloud platform (AWS, GCP, ...):** add one file to
`connectors/` implementing `BasePlatformConnector`, then add one entry to
`CLOUD_CONNECTOR_REGISTRY`. No other files change.
