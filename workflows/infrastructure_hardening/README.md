# infrastructure_hardening

Infrastructure Hardening Maturity Assessment Workflow.

Assesses infrastructure security hardening maturity across a connected
**version control system** (GitHub / Azure DevOps) and a connected
**cloud platform** (Azure, extensible to AWS/GCP) across 5 progressive
maturity levels, using **fail-fast** logic: assessment stops at the
first level that does not pass.

---

## API usage

```
POST /api/execute/infrastructure_hardening
```

### Request body

```json
{
  "input_data": {
    "assessment_id": "44444444-4444-4444-4444-444444444444",
    "vcs_type": "github",
    "repository": "myorg/myrepo",
    "vcs_credentials": {
      "token": "<github-pat-or-ado-pat>",
      "organization": "<ado-org, ado only>",
      "project": "<ado-project, ado only>",
      "branch": "main"
    },
    "cloud_type": "azure",
    "cloud_credentials": {
      "access_token": "<azure-arm-bearer-token>",
      "subscription_id": "<azure-subscription-id>",
      "resource_group": "<azure-resource-group>"
    }
  }
}
```

### Response (returned immediately, processing runs in background)

```json
{
  "workflow": "infrastructure_hardening",
  "status": "in_progress",
  "result": null,
  "error": null,
  "timestamp": "2026-07-03T12:00:00.000000"
}
```

The final result is persisted to the `assessment_result` table (see
**Database Persistence** below) — poll or fetch by `assessment_id` /
`result_id` per the existing assessment result API.

---

## Levels table

| Level | Focus                                                             | Score Range |
|-------|--------------------------------------------------------------------|-------------|
| 1     | Access Control & Basic Encryption                                  | 0.0 – 1.0   |
| 2     | Virtualization, Isolation & Data Protection                        | 1.0 – 2.0   |
| 3     | Advanced Traffic Control, Immutability & Infrastructure as Code    | 2.0 – 3.0   |
| 4     | Advanced Hardening, Developer Parity & Chaos Testing               | 3.0 – 4.0   |
| 5     | Enterprise-Grade Security & Adaptive Protection                    | 4.0 – 5.0   |

### Criteria per level

**Level 1** — MFA for Admins · Simple Access Control (admin count ≤5, documented reviews) · Edge Encryption in Transit

**Level 2** — Virtualized Environments · Automated Backups · Baseline Hardening (CIS K8s Bench L1-2) · Isolated Networks · Universal MFA · Dedicated Security Account · Encryption at Rest · Test & Production Environments · Resource Limits on VMs

**Level 3** — Egress Traffic Filtering · Immutable Infrastructure · Infrastructure as Code · System Event Limitation · RBAC · Internal Encryption in Transit (mTLS) · WAF Baseline (monitoring mode)

**Level 4** — Advanced Environment Hardening (CIS K8s Bench L2-3) · Production-Near Local Environments · Chaos Engineering · WAF Medium Protection

**Level 5** — WAF Advanced Protection (ML-driven anomaly detection, dynamic rule sets)

---

## Credentials reference

| Field | Platform | Required | Notes |
|---|---|---|---|
| `vcs_type` | — | Yes | `"github"` or `"azure_devops"` |
| `vcs_credentials.token` | GitHub / Azure DevOps | Yes | PAT with repo/org read scope |
| `vcs_credentials.organization` | Azure DevOps | Yes (ADO only) | ADO organization name |
| `vcs_credentials.project` | Azure DevOps | Yes (ADO only) | ADO project name |
| `vcs_credentials.branch` | GitHub | No | Defaults to `main` |
| `cloud_type` | — | Yes | `"azure"` (AWS/GCP reserved for future use) |
| `cloud_credentials.access_token` | Azure | Yes | ARM-scoped bearer token |
| `cloud_credentials.subscription_id` | Azure | Yes | Azure subscription ID |
| `cloud_credentials.resource_group` | Azure | Yes | Resource group to assess |

---

## Connector guide

Two independent connector registries live in `connectors/__init__.py`:

```python
VCS_CONNECTOR_REGISTRY = {
    "github": GitHubConnector,
    "azure_devops": AzureDevOpsConnector,
}
CLOUD_CONNECTOR_REGISTRY = {
    "azure": AzureCloudConnector,
}
```

Both connector families write into the **same shared `PlatformData`**
object (see `connectors/base.py`) so the LLM level nodes see one unified
picture combining code-platform evidence and cloud-infrastructure
evidence.

**To add a new VCS platform:** create `connectors/<platform>.py`
implementing `BaseVCSConnector` (`health_check()` + `collect()`), then
add one entry to `VCS_CONNECTOR_REGISTRY`.

**To add a new cloud platform (AWS, GCP, ...):** create
`connectors/<platform>.py` implementing `BaseCloudConnector`, then add
one entry to `CLOUD_CONNECTOR_REGISTRY`. No other files change.

---

## Database Persistence

Two-stage lifecycle, per `AssessmentResultRepository`:

- **At start** (`collect_platform_data_node`): inserts a record with
  `status="IN_PROGRESS"` via `insert_assessment_result_returning_id`,
  and the returned `result_id` is threaded through workflow state.
- **At completion** (`format_result_node`): updates the record via
  `update_assessment_result` with `status="COMPLETED"` (or `"FAILED"`
  if an `error_message` is present anywhere upstream), final
  `domain_score`, `reasoning`, and `improvement_recommendations`.
- **Unhandled errors**: caught by `BaseWorkflow.run`, which marks the
  record `FAILED` if `result_id` is present in state.

---

## `level_wise_criteria` field reference

Always present in the final result, covering **all 5 levels**:

- **Evaluated levels** (reached by the assessment): `checked: true`,
  full `score`/`reasoning`, and a `criteria` list with each item as
  `{"name", "status": "PASSED"|"FAILED", "reason", "evidence"}`.
- **Skipped levels** (not reached because an earlier level failed, or
  an error halted the run): `checked: false`, `score: null`, and a
  `criteria` list built from the canonical `LEVEL_CRITERIA_NAMES` for
  that level, each marked `"status": "NOT_CHECKED"` with a `reason`
  naming the exact level that caused the halt.

## Final `result` shape (project output spec)

```json
{
  "workflow_name": "infrastructure_hardening",
  "maturity_level": 2,
  "score": 1.3,
  "score_range": "1.0-2.0",
  "assessment_details": {
    "passed_criteria": [{"criterion": "...", "evidence": "..."}],
    "failed_criteria": [{"criterion": "...", "reason": "...", "evidence": "..."}],
    "reasoning": "..."
  },
  "improvement_recommendations": [
    {"gap": "...", "action": "...", "priority": "high|medium|low", "estimated_effort": "low|medium|high", "related_level": 3}
  ],
  "platform_details": {
    "version_control": "github",
    "cloud_platform": "azure",
    "assessment_timestamp": "2026-07-03T12:00:00Z"
  },
  "level_wise_criteria": [ "...see above, all 5 levels..." ],
  "level_breakdown": {"1": {"passed": true, "score": 1.0}, "2": {"passed": false, "score": 1.3}},
  "platform": {"api_call_log": ["GET https://api.github.com/orgs/myorg", "..."]}
}
```

Note: `assessment_details.passed_criteria` / `failed_criteria` at the
top level reflect only the **current (final) level's** LLM output, per
the project output spec. The full per-level breakdown across all 5
levels lives in `level_wise_criteria`.
