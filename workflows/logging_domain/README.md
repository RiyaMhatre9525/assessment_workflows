# logging_domain — Logging Maturity Assessment

Assesses logging infrastructure maturity across a connected **Version Control
System** (source of pipeline/IaC/application logging configuration) and a
connected **Cloud Platform** (source of actual centralized log collection,
storage, and monitoring configuration), using a 5-level progressive
fail-fast maturity model.

This workflow uses the **dual connector registry** pattern: a VCS connector
and a Cloud connector are queried independently and their signals are merged
before each level is assessed.

## API usage

```
POST /api/execute/logging_domain
{
  "input_data": {
    "assessment_id": "33333333-3333-3333-3333-333333333333",
    "vcs_platform_type": "github",
    "repository": "myorg/myrepo",
    "branch": "main",
    "vcs_credentials": {
      "token": "<github-pat>"
    },
    "cloud_platform_type": "azure",
    "cloud_credentials": {
      "tenant_id": "<aad-tenant-id>",
      "client_id": "<service-principal-client-id>",
      "client_secret": "<service-principal-client-secret>",
      "subscription_id": "<azure-subscription-id>"
    }
  }
}
```

For Azure DevOps as the VCS platform, use:
```json
{
  "vcs_platform_type": "azure_devops",
  "repository": "myorg/myproject/myrepo",
  "branch": "main",
  "vcs_credentials": { "organization": "myorg", "pat": "<azure-devops-pat>" }
}
```

### Response (immediate, async processing)
```json
{
  "workflow": "logging_domain",
  "status": "in_progress",
  "result": null,
  "error": null,
  "timestamp": "2026-07-06T12:00:00.000000"
}
```

## Levels

| Level | Focus Area | Score Range |
|-------|------------|-------------|
| 1 | Centralized System Logging | 0.0 – 1.0 |
| 2 | Centralized Application Logging & Security Events | 1.0 – 2.0 |
| 3 | Log Analysis & Visualization | 2.0 – 3.0 |
| 4 | Reserved — criteria not yet defined (auto-pass placeholder) | 3.0 – 4.0 |
| 5 | Security Event Correlation & PII Logging Compliance | 4.0 – 5.0 |

Assessment is **fail-fast**: if a level's criteria are not fully met, the
workflow stops and returns the maturity score for the last fully-passed
level. Level 4 has no criteria defined yet, so it always auto-passes with a
placeholder note (per project convention) until real criteria are supplied.

## Final result shape

```json
{
  "domain": "Logging",
  "maturity_level": 2,
  "score": 1.6,
  "score_range": "1.0-2.0",
  "assessment_details": {
    "passed_criteria": [
      {"level": 1, "criteria": "Centralized log collection from multiple sources", "status": "PASSED"}
    ],
    "failed_criteria": [
      {"level": 3, "criteria": "Attack detection mechanisms", "status": "FAILED", "reason": "..."}
    ],
    "overall_reasoning": "..."
  },
  "improvement_recommendations": [
    {
      "gap": "...",
      "current_limitation": "...",
      "recommended_action": "...",
      "related_level": 3,
      "priority": "high"
    }
  ],
  "level_wise_criteria": [
    {
      "level": 1, "level_name": "Centralized System Logging",
      "status": "PASSED", "checked": true, "score": 1.0,
      "reasoning": "...",
      "criteria": [
        {"name": "Centralized log collection from multiple sources", "status": "PASSED", "reason": "..."}
      ]
    }
  ],
  "level_breakdown": {
    "1": {"passed": true, "score": 1.0},
    "2": {"passed": true, "score": 1.6}
  },
  "platform": {
    "api_call_log": ["GET https://api.github.com/...", "POST https://login.microsoftonline.com/..."]
  }
}
```

`level_wise_criteria` always covers all 5 levels: evaluated levels show full
`{name, status, reason}` per criterion; skipped levels show the canonical
criteria names from `LEVEL_CRITERIA_NAMES` with `status: NOT_CHECKED` and a
reason naming the level that halted the assessment.

## Credentials reference

| Field | Platform | Description |
|---|---|---|
| `vcs_platform_type` | — | `"github"` or `"azure_devops"` |
| `vcs_credentials.token` | github | GitHub Personal Access Token |
| `vcs_credentials.organization` | azure_devops | Azure DevOps organization name |
| `vcs_credentials.pat` | azure_devops | Azure DevOps Personal Access Token |
| `cloud_platform_type` | — | `"azure"` (extensible to `aws`, `gcp`) |
| `cloud_credentials.tenant_id` | azure | Azure AD tenant ID |
| `cloud_credentials.client_id` | azure | Service Principal client ID |
| `cloud_credentials.client_secret` | azure | Service Principal client secret |
| `cloud_credentials.subscription_id` | azure | Azure subscription ID |

## Connector guide

- `connectors/base.py` — `BaseVCSConnector`, `BaseCloudConnector` ABCs +
  shared dataclasses (`VCSLoggingData`, `CloudLoggingData`, etc.)
- `connectors/github.py` — `GitHubVCSConnector`
- `connectors/azure_devops.py` — `AzureDevOpsVCSConnector`
- `connectors/azure.py` — `AzureCloudConnector` (Service Principal auth)
- `connectors/__init__.py` — `VCS_CONNECTOR_REGISTRY` and
  `CLOUD_CONNECTOR_REGISTRY` dicts

**To add a new VCS platform:** add one connector file implementing
`BaseVCSConnector`, then add one entry to `VCS_CONNECTOR_REGISTRY`.

**To add a new cloud platform (e.g. AWS, GCP):** add one connector file
implementing `BaseCloudConnector`, then add one entry to
`CLOUD_CONNECTOR_REGISTRY`. No other files need to change.
