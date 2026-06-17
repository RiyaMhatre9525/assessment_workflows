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
Once background processing finishes, results are automatically saved to the database table `assessment_result`.

* **Successful Completion (Status: `COMPLETED`)**:
  ```json
  {
    "maturity_level": 2,
    "score": 1.3,
    "score_range": "1.0–2.0",
    "assessment_details": {
      "passed_criteria": ["Image digests used"],
      "failed_criteria": ["No SBOM generation step found"],
      "reasoning": "The platform uses image digests for container images, but there is no enforcement of immutability..."
    },
    "improvement_recommendations": [
      {
        "gap": "Immutability enforcement for container images",
        "action": "Implement registry policies to prevent overwriting of tags",
        "priority": "high"
      }
    ],
    "level_breakdown": {
      "1": {"passed": true, "score": 1.0},
      "2": {"passed": false, "score": 1.3}
    }
  }
  ```
* **Failure (Status: `FAILED`)**:
  If execution fails unexpectedly, a record is still created with status `FAILED` and error details written under `reasoning` / `additional_info`.


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
├── config.py          ← scoring constants + LLM prompts
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
