# Patch Management Assessment Workflow

Assesses Patch Management maturity for a project by collecting evidence from
SCM platforms (GitHub, Azure DevOps) and, where credentials permit, cloud
container registries (currently Azure Container Registry).

This is a **fail-fast** workflow: execution stops at the first level whose
controls are not fully satisfied, and the achieved maturity level is returned.

## API Usage

```
POST /api/execute/patch_management
```

```json
{
  "input_data": {
    "assessment_id": "11111111-1111-1111-1111-111111111111",
    "platform": "github",
    "credentials": {
      "token": "<personal-access-token>",
      "repository": "myorg/myrepo"
    }
  }
}
```

Azure DevOps example, with optional Azure Container Registry credentials for
image-lifecycle checks (Level 2 / Level 4):

```json
{
  "input_data": {
    "assessment_id": "22222222-2222-2222-2222-222222222222",
    "platform": "azure_devops",
    "credentials": {
      "token": "<azure-devops-pat>",
      "organization": "myorg",
      "project": "myproject",
      "repository": "myrepo",
      "registry_name": "myregistry",
      "registry_access_token": "<acr-bearer-token>"
    }
  }
}
```

### Immediate response (async processing)

```json
{
  "workflow": "patch_management",
  "status": "in_progress",
  "result": null,
  "error": null,
  "timestamp": "2026-06-29T10:00:00.000000"
}
```

The full result is persisted to the `assessment_result` table once processing
completes.

## Levels

| Level | Name | Controls | Score Range |
|---|---|---|---|
| 1 | Patch Policy & Automated Pull Requests | Patch Policy; Automated Pull Requests | 0.0 – 1.0 |
| 2 | Automated Merge, Nightly Builds & Image Hygiene | Automated Merge; Nightly Base Image Builds; Reduction of Attack Surface; Maximum Lifetime of Images | 1.0 – 2.0 |
| 3 | Automated Deployment | Automated Deployment | 2.0 – 3.0 |
| 4 | Short Maximum Lifetime for Images | Short Maximum Lifetime for Images | 3.0 – 4.0 |
| 5 | Not Applicable | None defined — auto-passed | 4.0 – 5.0 |

## Credentials reference

| Platform | Required keys | Optional keys (enable extra checks) |
|---|---|---|
| `github` | `token`, `repository` (`org/repo`) | — |
| `azure_devops` | `token`, `organization`, `project`, `repository` | `registry_name`, `registry_access_token` (Azure Container Registry) |

Credentials are never logged. Only request URLs (no secrets) are recorded in
`platform.api_call_log`.

## Final result fields

```json
{
  "workflow": "patch_management",
  "maturity_level": 2,
  "score": 1.8,
  "status": "FAILED_AT_LEVEL_2",
  "summary": "...",
  "assessment": {
    "level_1": {"status": "PASS", "controls": [...]},
    "level_2": {"status": "FAIL", "controls": [...]}
  },
  "missing_controls": [{"level": 2, "control": "Maximum Lifetime of Images", "reason": "..."}],
  "recommendations": [{"level": 2, "gap": "...", "action": "...", "priority": "high"}],
  "limitations": ["Registry inaccessible; image lifetime could not be verified."],
  "level_wise_criteria": [
    {
      "level": 1, "level_name": "Patch Policy & Automated Pull Requests",
      "status": "PASSED", "checked": true, "score": 1.0, "reasoning": "...",
      "criteria": [{"name": "Patch Policy", "status": "PASSED", "reason": "..."}]
    },
    {
      "level": 3, "level_name": "Automated Deployment",
      "status": "NOT_CHECKED", "checked": false, "score": null, "reasoning": null,
      "criteria": [{"name": "Automated Deployment", "status": "NOT_CHECKED", "reason": "Level 2 did not pass — assessment halted before reaching this level."}]
    }
  ],
  "level_breakdown": {"1": {"passed": true, "score": 1.0}, "2": {"passed": false, "score": 1.8}},
  "platform": {"platform_type": "github", "repository": "myorg/myrepo", "api_call_log": ["GET https://api.github.com/..."]}
}
```

- `level_wise_criteria` always covers all 5 levels (PASSED / FAILED / NOT_CHECKED).
- `level_breakdown` is a compact `{passed, score}` map for levels that were evaluated.
- `limitations` surfaces any control that could not be verified via the available
  APIs (e.g. Dockerfile inspection unavailable, container registry inaccessible).

## Adding a new SCM or cloud platform

1. Create `connectors/<platform>.py` implementing `BasePlatformConnector`
   (`health_check()` + `collect()`), returning a `PatchManagementPlatformData`.
2. Register it in `connectors/__init__.py`'s `CONNECTOR_REGISTRY`.

No other files change — `nodes.py`, `graph.py`, and `config.py` are platform-agnostic.

## Error handling

- Invalid/unsupported `platform` or missing `credentials.repository` → synchronous
  `ValueError` from `initialize_state`, returned as `WorkflowResponse(status="error")`.
- Authentication failure / unreachable platform → `collect_platform_data_node`
  stops the assessment and records status `FAILED`.
- Any node exception → caught, `stop_assessment=True`, `error_message` set;
  `format_result_node` still runs and returns a structured `ERROR` result.
- Unhandled exceptions are caught by `BaseWorkflow.run`, which marks the
  database record `FAILED`.
