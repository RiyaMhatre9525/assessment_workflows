# deployment_domain — Deployment Maturity Assessment

Progressive 5-level workflow that evaluates deployment maturity across version control and cloud platforms using a fail-fast model.

---

## API Usage

```bash
POST /api/execute/deployment_domain
Content-Type: application/json

{
  "input_data": {
    "assessment_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    "platform_type": "github",
    "repository": "myorg/myrepo",
    "branch": "main",
    "credentials": {
      "token": "<github-pat>"
    }
  }
}
```

Immediate response (async processing in background):
```json
{
  "workflow": "deployment_domain",
  "status": "in_progress",
  "result": null,
  "error": null,
  "timestamp": "2026-06-18T10:00:00.000000"
}
```

---

## Maturity Levels

| Level | Score Range | Focus Area | Criteria |
|-------|-------------|------------|----------|
| 1 | 0.0 – 1.0 | Deployment Process Foundation | Defined process · Automated deployment · Production component inventory |
| 2 | 1.0 – 2.0 | Artifact Management & Component Trust | Artifact inventory · Component trust evaluation · Secrets management · Decommissioning process |
| 3 | 2.0 – 3.0 | Deployment Safety & Dependency Management | Dependency inventory · Credential handover (encrypted) · Rolling updates / zero-downtime |
| 4 | 3.0 – 4.0 | Environment Consistency & Feature Control | Same artifact across environments · Feature toggles |
| 5 | 4.0 – 5.0 | Advanced Deployment Strategy | Blue/Green deployment |

Assessment stops at the first failed level. All criteria within a level must pass to advance.

---

## Database Persistence

The workflow implements a two-stage database persistence lifecycle:
- **At start**: A database record is immediately created in the `assessment_result` table with `status="IN_PROGRESS"` using `AssessmentResultRepository.insert_assessment_result_returning_id`.
- **At completion/failure**: Once background processing finishes (or fails), the same database entry is updated to status `COMPLETED` or `FAILED` with the full results using `AssessmentResultRepository.update_assessment_result`.

---

## Result Schema


**Successful Completion (Status: `COMPLETED`)**:
```json
{
  "maturity_level": 2,
  "score": 1.4,
  "score_range": "1.0–2.0",
  "assessment_details": {
    "passed_criteria": [
      {"name": "Artifact inventory",         "reason": "Container image inventory documented in the repo wiki."},
      {"name": "Component trust evaluation", "reason": "Approved artifact whitelist found in pipeline configuration."}
    ],
    "failed_criteria": [
      {"name": "Secrets management",      "reason": "No secrets management tool (Vault, Key Vault) detected in the pipeline."},
      {"name": "Decommissioning process", "reason": "No documented process for retiring containers or Kubernetes resources found."}
    ],
    "reasoning": "Artifact inventory and trust evaluation are in place, but secrets management and decommissioning are absent."
  },
  "improvement_recommendations": [
    {
      "gap": "Secrets management missing",
      "action": "Integrate HashiCorp Vault or Azure Key Vault for all environment secrets.",
      "priority": "high",
      "estimated_effort": "medium"
    }
  ],
  "level_wise_criteria": [
    {
      "level": 1,
      "level_name": "Deployment Process Foundation",
      "status": "PASSED",
      "checked": true,
      "score": 1.0,
      "reasoning": "All three foundation criteria fully satisfied.",
      "criteria": [
        {"name": "Defined deployment process",          "status": "PASSED", "reason": "Runbook and approval workflow documented in the repository."},
        {"name": "Automated deployment",                "status": "PASSED", "reason": "CI/CD pipeline automates all deployment steps via GitHub Actions."},
        {"name": "Inventory of production components",  "status": "PASSED", "reason": "Service catalogue lists all production applications with versions."}
      ]
    },
    {
      "level": 2,
      "level_name": "Artifact Management & Component Trust",
      "status": "FAILED",
      "checked": true,
      "score": 1.4,
      "reasoning": "Artifact inventory and trust controls are present, but secrets management and decommissioning process are missing.",
      "criteria": [
        {"name": "Artifact inventory",         "status": "PASSED", "reason": "Container image inventory documented and version-controlled."},
        {"name": "Component trust evaluation", "status": "PASSED", "reason": "Approved artifact whitelist enforced in pipeline configuration."},
        {"name": "Secrets management",         "status": "FAILED", "reason": "No secrets management tool detected; credentials appear hardcoded."},
        {"name": "Decommissioning process",    "status": "FAILED", "reason": "No documented retirement process for containers or Kubernetes resources."}
      ]
    },
    {
      "level": 3,
      "level_name": "Deployment Safety & Dependency Management",
      "status": "NOT_CHECKED",
      "checked": false,
      "score": null,
      "reasoning": null,
      "criteria": [
        {"name": "Production dependency inventory",         "status": "NOT_CHECKED", "reason": "Level 2 (Artifact Management & Component Trust) did not pass — assessment halted before reaching this level."},
        {"name": "Credential handover (encrypted at rest)", "status": "NOT_CHECKED", "reason": "Level 2 (Artifact Management & Component Trust) did not pass — assessment halted before reaching this level."},
        {"name": "Rolling updates / zero-downtime",         "status": "NOT_CHECKED", "reason": "Level 2 (Artifact Management & Component Trust) did not pass — assessment halted before reaching this level."}
      ]
    },
    {
      "level": 4,
      "level_name": "Environment Consistency & Feature Control",
      "status": "NOT_CHECKED",
      "checked": false,
      "score": null,
      "reasoning": null,
      "criteria": [
        {"name": "Same artifact across environments", "status": "NOT_CHECKED", "reason": "Level 2 (Artifact Management & Component Trust) did not pass — assessment halted before reaching this level."},
        {"name": "Feature toggles",                   "status": "NOT_CHECKED", "reason": "Level 2 (Artifact Management & Component Trust) did not pass — assessment halted before reaching this level."}
      ]
    },
    {
      "level": 5,
      "level_name": "Advanced Deployment Strategy",
      "status": "NOT_CHECKED",
      "checked": false,
      "score": null,
      "reasoning": null,
      "criteria": [
        {"name": "Blue/Green deployment", "status": "NOT_CHECKED", "reason": "Level 2 (Artifact Management & Component Trust) did not pass — assessment halted before reaching this level."}
      ]
    }
  ],
  "level_breakdown": {
    "1": {"passed": true,  "score": 1.0},
    "2": {"passed": false, "score": 1.4}
  },
  "api_call_log": [
    "GET https://api.github.com/repos/myorg/myrepo/actions/workflows"
  ]
}
```

**Failure (Status: `FAILED`)**:
If execution fails unexpectedly, a record is still created with status `FAILED` and error details written under `reasoning` / `additional_info`.

---

## `level_wise_criteria` Field

Every response includes `level_wise_criteria` — a complete list covering **all 5 levels**, regardless of where the assessment stopped.

| Field | Description |
|---|---|
| `level` | Level number (1–5) |
| `level_name` | Human-readable level title |
| `status` | `PASSED` / `FAILED` / `NOT_CHECKED` |
| `checked` | `true` if the LLM evaluated this level; `false` if skipped |
| `score` | Score within the level's range, or `null` if not checked |
| `reasoning` | LLM's overall explanation for the level, or `null` if not checked |
| `criteria` | Array of individual criterion objects (see below) |

Each **criterion** object:

| Field | Description |
|---|---|
| `name` | Criterion name as identified by the LLM |
| `status` | `PASSED` / `FAILED` / `NOT_CHECKED` |
| `reason` | LLM-supplied one-sentence explanation (or skip reason for NOT_CHECKED) |

---

## Credentials Reference

### GitHub
| Key | Description |
|-----|-------------|
| `token` | GitHub Personal Access Token with `repo` and `read:packages` scopes |

### Azure DevOps
| Key | Description |
|-----|-------------|
| `token` | Azure DevOps Personal Access Token |
| `organization` | Azure DevOps organisation name |

---

## Adding a New Platform Connector

1. Create `connectors/<platform>.py` implementing `BasePlatformConnector`.
2. Add one entry to `CONNECTOR_REGISTRY` in `connectors/__init__.py`.
3. No other files need to change.

---

## File Structure

```
workflows/deployment_domain/
├── __init__.py
├── README.md
├── config.py          ← scoring constants + LEVEL_CRITERIA_NAMES + LLM prompts
├── nodes.py           ← async node functions (one per level) + format_result_node
├── graph.py           ← StateGraph wiring + DeploymentMaturityWorkflow class
└── connectors/
    ├── __init__.py    ← CONNECTOR_REGISTRY
    ├── base.py        ← BasePlatformConnector + DeploymentPlatformData dataclasses
    ├── github.py      ← GitHub REST API connector
    └── azure_devops.py← Azure DevOps REST API connector
```

---

## Registering in the API

In `api/routes.py`:

```python
from workflows.deployment_domain.graph import DeploymentMaturityWorkflow

WORKFLOWS = {
    "build_domain":      PipelineMaturityWorkflow(),
    "deployment_domain": DeploymentMaturityWorkflow(),   # ← registered here
}
```
