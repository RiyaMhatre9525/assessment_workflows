# Dynamic Depth for Infrastructure Assessment Workflow

Assesses infrastructure security maturity by collecting evidence from SCM
platforms (GitHub, Azure DevOps) and cloud providers (Azure).

Fail-fast workflow — stops at the first level whose controls are not met.

## API Usage

```
POST /api/execute/Dynamic_Depth_for_Infrastructure
```

### GitHub + Azure example

```json
{
  "input_data": {
    "assessment_id": "11111111-1111-1111-1111-111111111111",
    "source_platform": "github",
    "cloud_platform": "azure",
    "credentials": {
      "token": "<github-pat>",
      "repository": "myorg/myrepo",
      "subscription_id": "<azure-subscription-id>",
      "tenant_id": "<azure-tenant-id>",
      "client_id": "<azure-client-id>",
      "client_secret": "<azure-client-secret>"
    }
  }
}
```

### Azure DevOps + Azure example

```json
{
  "input_data": {
    "assessment_id": "22222222-2222-2222-2222-222222222222",
    "source_platform": "azure_devops",
    "cloud_platform": "azure",
    "organization": "myorg",
    "project": "myproject",
    "credentials": {
      "token": "<azure-devops-pat>",
      "organization": "myorg",
      "project": "myproject",
      "repository": "myrepo"
    }
  }
}
```

### Immediate response (async processing)

```json
{
  "workflow": "Dynamic_Depth_for_Infrastructure",
  "status": "in_progress",
  "result": null
}
```

## Maturity Levels

| Level | Name | Controls | Score Range |
|---|---|---|---|
| 1 | Baseline (auto-pass) | N/A | 0.0 – 1.0 |
| 2 | Infrastructure Exposure & Configuration | Exposed Services, Network Segmentation, Cloud Configuration | 1.0 – 2.0 |
| 3 | Workload & Authentication Security | Unauthorized Installation, Weak Password | 2.0 – 3.0 |
| 4 | Load Testing | Load Testing | 3.0 – 4.0 |
| 5 | Unused Resource Analysis | Unused Resources | 4.0 – 5.0 |

## Credentials Reference

| Platform | Required keys | Optional keys (enable cloud checks) |
|---|---|---|
| `github` | `token`, `repository` | `subscription_id`, `tenant_id`, `client_id`, `client_secret` |
| `azure_devops` | `token`, `organization`, `project`, `repository` | same Azure keys above |

Cloud credentials are optional — without them, Level 2 Cloud Configuration
and Level 5 Unused Resources checks rely on pipeline evidence only.

## Final Result Fields

```json
{
  "workflow_name": "Dynamic_Depth_for_Infrastructure",
  "maturity_level": 2,
  "score": 1.6,
  "status": "Failed at Level 3",
  "reason": ["Exposed services scanning configured.", "NSG rules found."],
  "passed_checks": ["Test for Exposed Services", "Test Network Segmentation"],
  "failed_checks": ["Unauthorized Installation Test"],
  "recommendations": ["Add Trivy image scanning to your pipeline."],
  "improvement_actions": ["Configure OPA/Kyverno admission webhooks."],
  "next_maturity_level": 3,
  "level_wise_criteria": [...],
  "level_breakdown": {"1": {"passed": true, "score": 1.0}},
  "platform": {"source_platform_type": "github", "repository": "org/repo", "api_call_log": [...]}
}
```

## Adding a New Platform

**New SCM platform:**
1. Create `connectors/<platform>.py` implementing `BaseInfraSCMConnector`
2. Add to `SCM_CONNECTOR_REGISTRY` in `connectors/__init__.py`

**New cloud provider:**
1. Create `connectors/<cloud>.py` implementing `BaseInfraCloudConnector`
2. Add to `CLOUD_CONNECTOR_REGISTRY` in `connectors/__init__.py`

No other files change.

## routes.py patch

```python
from workflows.Dynamic_Depth_for_Infrastructure.graph import DynamicDepthForInfrastructureWorkflow

WORKFLOWS = {
    # ... existing workflows ...
    "Dynamic_Depth_for_Infrastructure": DynamicDepthForInfrastructureWorkflow(),
}
```
