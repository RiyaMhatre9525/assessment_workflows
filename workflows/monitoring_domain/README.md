# monitoring_domain — Monitoring & Observability Maturity Assessment

Assesses monitoring/observability maturity across a connected **Version
Control System** (source of monitoring-as-code configuration) and a
connected **Cloud Platform** (source of live alerting/cost/dashboard
configuration), across 5 progressive maturity levels with fail-fast logic.

- **Key:** `monitoring_domain`
- **Class:** `MonitoringMaturityWorkflow`
- **VCS connectors:** GitHub, Azure DevOps (extensible)
- **Cloud connectors:** Azure (extensible to AWS, GCP)

## API usage

```
POST /api/execute/monitoring_domain
{
  "input_data": {
    "assessment_id": "44444444-4444-4444-4444-444444444444",
    "vcs_platform_type": "github",
    "cloud_platform_type": "azure",
    "repository": "myorg/myrepo",
    "vcs_credentials": {
      "token": "<github-pat-or-ado-pat>"
    },
    "cloud_credentials": {
      "tenant_id": "<azure-tenant-id>",
      "client_id": "<service-principal-client-id>",
      "client_secret": "<service-principal-client-secret>",
      "subscription_id": "<azure-subscription-id>"
    }
  }
}
```

For `vcs_platform_type: "azure_devops"`, `vcs_credentials` must instead be:
```json
{
  "organization": "<ado-org>",
  "project": "<ado-project>",
  "token": "<ado-pat>"
}
```

### Response (returned immediately, async processing)

```json
{
  "workflow": "monitoring_domain",
  "status": "in_progress",
  "result": null,
  "error": null,
  "timestamp": "2026-07-07T12:00:00.000000"
}
```

The final result is persisted to the `assessment_result` table (two-stage
lifecycle: `IN_PROGRESS` → `COMPLETED`/`FAILED`) and looked up by
`result_id`.

## Credentials reference

| Platform family | Field | Notes |
|---|---|---|
| VCS: GitHub | `token` | Personal access token with `repo` + code search scope |
| VCS: Azure DevOps | `organization`, `project`, `token` | PAT with Code (Read) scope |
| Cloud: Azure | `tenant_id`, `client_id`, `client_secret`, `subscription_id` | Service Principal, client-credentials flow. ARM tokens are short-lived (~1hr) and are minted per-request internally — store the Service Principal credentials long-term, not a raw token. |

## Levels table

| Level | Focus Area | Score Range |
|---|---|---|
| 1 | Basic Monitoring Foundation | 0.0 – 1.0 |
| 2 | Alerting & Cost Control | 1.0 – 2.0 |
| 3 | Advanced Observability & Intelligence | 2.0 – 3.0 |
| 4 | Advanced Security & Coverage Metrics | 3.0 – 4.0 |
| 5 | Metrics-Driven Testing Integration | 4.0 – 5.0 |

Assessment is **fail-fast**: if a level's criteria are not all met, the
assessment stops immediately and the score for that level is returned;
subsequent levels are marked `NOT_CHECKED`.

## `final_result` field reference

```json
{
  "workflow_domain": "Monitoring",
  "maturity_level": 2,
  "score": 1.3,
  "score_range": "1.0-2.0",
  "assessment_details": {
    "passed_criteria": [{"name": "...", "reason": "..."}],
    "failed_criteria": [{"name": "...", "reason": "..."}],
    "reasoning": "..."
  },
  "improvement_recommendations": [
    {"gap": "...", "action": "...", "priority": "high|medium|low"}
  ],
  "level_wise_criteria": [
    {
      "level": 1, "level_name": "Basic Monitoring Foundation",
      "status": "PASSED", "checked": true, "score": 1.0,
      "reasoning": "...",
      "criteria": [{"name": "...", "status": "PASSED", "reason": "..."}]
    },
    {
      "level": 3, "level_name": "Advanced Observability & Intelligence",
      "status": "NOT_CHECKED", "checked": false, "score": null, "reasoning": null,
      "criteria": [{"name": "...", "status": "NOT_CHECKED", "reason": "Level 2 ... did not pass — assessment halted before reaching this level."}]
    }
  ],
  "level_breakdown": {
    "1": {"passed": true, "score": 1.0},
    "2": {"passed": false, "score": 1.3}
  },
  "platform_api_call_log": {
    "vcs": ["GET https://api.github.com/repos/.../contents/prometheus.yml", "..."],
    "cloud": ["GET https://management.azure.com/subscriptions/.../metricAlerts", "..."]
  }
}
```

- `level_wise_criteria` always covers all 5 levels (per WORKFLOW_TEMPLATE_CONTEXT.md rule 30) —
  evaluated levels show full `{name, status, reason}` per criterion; skipped
  levels show canonical criteria names with `NOT_CHECKED` and a reason
  naming the level that halted progress.
- `level_breakdown` is always the compact `{passed, score}` form (rule 27).
- `platform_api_call_log` is always included, split by `vcs` and `cloud`
  connector (rule 28, adapted for the dual-platform pattern).
- `workflow_domain`, `maturity_level`, `score`, `score_range`,
  `assessment_details`, and `improvement_recommendations` match the
  Monitoring Domain output spec exactly.

## Connector guide

- `connectors/base.py` — shared `BasePlatformConnector` ABC, `VCSMonitoringData`,
  `CloudMonitoringData`, and `MonitoringConfigFile` dataclasses.
- `connectors/github.py` / `connectors/azure_devops.py` — VCS connectors;
  registered in `VCS_CONNECTOR_REGISTRY`.
- `connectors/azure_cloud.py` — Cloud connector; registered in
  `CLOUD_CONNECTOR_REGISTRY`.
- To add a new VCS or Cloud platform: add one new connector file
  implementing `collect()` + `health_check()`, and add one entry to the
  relevant registry in `connectors/__init__.py`. No other files change.

## Files

```
workflows/monitoring_domain/
├── __init__.py
├── README.md
├── config.py
├── nodes.py
├── graph.py
└── connectors/
    ├── __init__.py
    ├── base.py
    ├── github.py
    ├── azure_devops.py
    └── azure_cloud.py
```

Apply `api_routes_patch.py` to `api/routes.py` to register the workflow.
