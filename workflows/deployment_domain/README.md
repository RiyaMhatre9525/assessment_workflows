# deployment_domain — Deployment Maturity Assessment

Progressive 5-level workflow that evaluates deployment maturity across version
control and cloud platforms using a fail-fast model.

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

| Level | Score Range | Focus Area |
|-------|-------------|------------|
| 1 | 0.0 – 1.0 | Deployment Process Foundation |
| 2 | 1.0 – 2.0 | Artifact Management & Component Trust |
| 3 | 2.0 – 3.0 | Deployment Safety & Dependency Management |
| 4 | 3.0 – 4.0 | Environment Consistency & Feature Control |
| 5 | 4.0 – 5.0 | Advanced Deployment Strategy (Blue/Green) |

Assessment stops at the first failed level. All criteria within a level must
pass to advance.

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

## Result Schema

```json
{
  "maturity_level": 2,
  "score": 1.4,
  "score_range": "1.0–2.0",
  "assessment_details": {
    "passed_criteria": ["..."],
    "failed_criteria": ["..."],
    "reasoning": "..."
  },
  "improvement_recommendations": [
    {
      "gap": "...",
      "action": "...",
      "priority": "high",
      "estimated_effort": "medium"
    }
  ],
  "level_breakdown": {
    "1": {"passed": true, "score": 1.0},
    "2": {"passed": false, "score": 1.4}
  },
  "api_call_log": ["GET https://api.github.com/..."]
}
```
