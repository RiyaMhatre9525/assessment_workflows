# Pipeline Maturity Assessment Workflow

Evaluates build pipeline maturity across version control and cloud platforms using a **progressive, fail-fast 5-level model**.

---

## API Usage

Workflows are executed asynchronously in the background. Calling the endpoint performs synchronous input validation and immediately returns an `"in_progress"` response.

```bash
POST /api/execute/build_domain
Content-Type: application/json

{
  "input_data": {
    "assessment_id": "33333333-3333-3333-3333-333333333333",
    "platform_type": "github",
    "repository": "myorg/myrepo",
    "branch": "main",
    "credentials": {
      "token": "<github-pat>"
    }
  }
}
```

For Azure DevOps:
```json
{
  "input_data": {
    "assessment_id": "33333333-3333-3333-3333-333333333333",
    "platform_type": "azure_devops",
    "repository": "MyProject/MyRepo",
    "branch": "main",
    "credentials": {
      "pat": "<ado-pat>",
      "organization": "mycompany",
      "project": "MyProject"
    }
  }
}
```

---

## Response & Persistence Format

### 1. API Response (Returned Immediately)
```json
{
  "workflow": "build_domain",
  "status": "in_progress",
  "result": null,
  "error": null,
  "timestamp": "2026-06-17T21:22:05.123456"
}
```

### 2. Database Persistence
Once background processing finishes, results are automatically saved to the `assessment_result` table.

**Successful Completion (Status: `COMPLETED`)**:
```json
{
  "maturity_level": 2,
  "score": 1.3,
  "score_range": "1.0–2.0",
  "assessment_details": {
    "passed_criteria": [
      {"name": "Image digests used", "reason": "Container images are pinned using SHA256 digests."}
    ],
    "failed_criteria": [
      {"name": "SBOM generation", "reason": "No SBOM tool step detected in any pipeline file."}
    ],
    "reasoning": "Digests detected but SBOM tool is absent from the pipeline."
  },
  "improvement_recommendations": [
    {
      "gap": "SBOM generation missing",
      "action": "Add a Trivy or Syft SBOM generation step to the build pipeline.",
      "priority": "high"
    }
  ],
  "level_wise_criteria": [
    {
      "level": 1,
      "level_name": "Build Process Definition",
      "status": "PASSED",
      "checked": true,
      "score": 1.0,
      "reasoning": "All three job types detected; security scan is blocking.",
      "criteria": [
        {"name": "Pipeline defined",           "status": "PASSED", "reason": "GitHub Actions YAML workflow found and well-structured."},
        {"name": "Build step exists",          "status": "PASSED", "reason": "npm run build step confirmed in the workflow."},
        {"name": "Test step exists",           "status": "PASSED", "reason": "pytest step present and executing on every push."},
        {"name": "Security scan step exists",  "status": "PASSED", "reason": "Trivy scanner configured as a required blocking step."}
      ]
    },
    {
      "level": 2,
      "level_name": "Artifact Pinning & SBOM",
      "status": "FAILED",
      "checked": true,
      "score": 1.3,
      "reasoning": "Image digests used but no SBOM generation or immutability enforcement found.",
      "criteria": [
        {"name": "Image digests used",   "status": "PASSED", "reason": "Images referenced by sha256 digest in deployment manifests."},
        {"name": "SBOM generation",      "status": "FAILED", "reason": "No Trivy, Syft, or CycloneDX SBOM step detected in pipeline."},
        {"name": "Artifact immutability","status": "FAILED", "reason": "Registry does not enforce tag immutability policies."}
      ]
    },
    {
      "level": 3,
      "level_name": "Code Signing & Enforcement",
      "status": "NOT_CHECKED",
      "checked": false,
      "score": null,
      "reasoning": null,
      "criteria": [
        {"name": "GPG commit signing",    "status": "NOT_CHECKED", "reason": "Level 2 (Artifact Pinning & SBOM) did not pass — assessment halted before reaching this level."},
        {"name": "Branch protection rules","status": "NOT_CHECKED", "reason": "Level 2 (Artifact Pinning & SBOM) did not pass — assessment halted before reaching this level."},
        {"name": "Require signed commits", "status": "NOT_CHECKED", "reason": "Level 2 (Artifact Pinning & SBOM) did not pass — assessment halted before reaching this level."}
      ]
    },
    {
      "level": 4,
      "level_name": "Supply-Chain Policy (criteria pending)",
      "status": "NOT_CHECKED",
      "checked": false,
      "score": null,
      "reasoning": null,
      "criteria": [
        {"name": "Policy definition", "status": "NOT_CHECKED", "reason": "Level 2 (Artifact Pinning & SBOM) did not pass — assessment halted before reaching this level."}
      ]
    },
    {
      "level": 5,
      "level_name": "Artifact Signing & Integrity",
      "status": "NOT_CHECKED",
      "checked": false,
      "score": null,
      "reasoning": null,
      "criteria": [
        {"name": "Cosign/in-toto signatures", "status": "NOT_CHECKED", "reason": "Level 2 (Artifact Pinning & SBOM) did not pass — assessment halted before reaching this level."},
        {"name": "Deployment verification",   "status": "NOT_CHECKED", "reason": "Level 2 (Artifact Pinning & SBOM) did not pass — assessment halted before reaching this level."}
      ]
    }
  ],
  "level_breakdown": {
    "1": {"passed": true,  "score": 1.0},
    "2": {"passed": false, "score": 1.3}
  },
  "platform": {
    "type": "github",
    "repository": "myorg/myrepo",
    "api_call_log": ["GET https://api.github.com/repos/myorg/myrepo/actions/workflows"]
  }
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

## Maturity Levels

| Level | Focus | Score Range |
|-------|-------|-------------|
| 1 | Build Process Definition (pipeline + build + test + security scan) | 0–1 |
| 2 | Artifact Pinning & SBOM (image digests + SBOM generation) | 1–2 |
| 3 | Code Signing & Enforcement (GPG commits + branch protection) | 2–3 |
| 4 | Supply-Chain Policy *(criteria pending — auto-passes)* | 3–4 |
| 5 | Artifact Signing & Integrity (Cosign / in-toto + deployment verification) | 4–5 |

Assessment **stops immediately** when a level fails.

---

## File Structure

```
workflows/build_domain/
├── __init__.py
├── README.md
├── config.py          ← scoring constants + LEVEL_CRITERIA_NAMES + LLM prompts
├── nodes.py           ← async node functions (one per level)
├── graph.py           ← StateGraph wiring + PipelineMaturityWorkflow class
└── connectors/
    ├── __init__.py    ← CONNECTOR_REGISTRY
    ├── base.py        ← BasePlatformConnector + shared data classes
    ├── github.py      ← GitHub REST API connector
    └── azure_devops.py← Azure DevOps REST API connector
```

---

## Adding a New Platform Connector

1. Create `connectors/my_platform.py` implementing `BasePlatformConnector`.
2. Implement `health_check()` and `collect()` — return a `PlatformData` object.
3. Register in `connectors/__init__.py`:

```python
from workflows.build_domain.connectors.my_platform import MyPlatformConnector

CONNECTOR_REGISTRY = {
    "github": GitHubConnector,
    "azure_devops": AzureDevOpsConnector,
    "my_platform": MyPlatformConnector,   # ← add here
}
```

No changes to `nodes.py`, `graph.py`, or `config.py` are needed.

---

## Credentials Reference

| Platform | Required keys |
|----------|--------------|
| `github` | `token` (PAT with `repo`, `read:packages`, `read:org` scopes) |
| `azure_devops` | `pat`, `organization`, optionally `project` |

---

## Registering in the API

In `api/routes.py`:

```python
from workflows.build_domain.graph import PipelineMaturityWorkflow

WORKFLOWS = {
    "test_search": TestSearchWorkflow(),
    "build_domain": PipelineMaturityWorkflow(),   # ← registered here
}
```
