# Static_Depth_for_Infrastructure

Assesses the **Static Security Maturity of Infrastructure** across 5
progressive levels by analyzing source code repositories (secrets, IaC,
pipeline tooling) and cloud infrastructure configuration (clusters, VMs,
registries, security posture). Uses a provider-adapter pattern for both
source control/DevOps platforms and cloud platforms so new providers can be
added without touching the assessment logic.

## Structural differences from the other workflows in this backend

- **Level 1 has real controls** ("Test for Stored Secrets in Build
  Artifacts", "Test for Stored Secrets in Source Code") — there is no
  baseline/"N/A" auto-pass level here.
- **Level 5 has no defined controls** per the spec — it always passes once
  Levels 1-4 have all fully passed, and has no LLM prompt.
- **Reporting convention:** `maturity_level` is the level the workflow was
  evaluating when it stopped (pass or fail) — matching
  `Development_and_Source_Control` / `Dynamic_Depth_for_Applications`, and
  differing from `Static_Depth_for_Applications` (which reports the highest
  *fully passed* level instead). This workflow's spec says "Return the
  current maturity level," so the halting level itself is what's reported.
- **Cloud evidence is central, not supplementary.** Several criteria
  (cluster deployment, cloud configuration, virtualized environment
  security) are fundamentally about deployed infrastructure and can only be
  evidenced via the cloud connector. If no `cloud_provider` is supplied,
  those criteria will almost always fail the evidence floor (see below).

## Evidence grounding (anti-hallucination safeguard)

Every level's LLM prompt requires citing specific matched evidence before
marking a criterion PASSED — but prompt instructions alone aren't reliable
enough. `nodes.py` also enforces this in code: `_apply_evidence_floor()`
downgrades any criterion the LLM marks PASSED to FAILED if
`detected_signals` (source control + cloud combined) has **no entry at all**
for that exact criterion name. This means a criterion can only ever pass if
a connector genuinely found a matching keyword, file, or cloud resource for
it — the LLM cannot single-handedly pass a criterion on vibes alone.

## API usage

```
POST /api/execute/Static_Depth_for_Infrastructure
```

```json
{
  "input_data": {
    "assessment_id": "66666666-6666-6666-6666-666666666666",
    "platform": {
      "source_control": "github",
      "cloud_provider": "azure"
    },
    "repository": "owner/repo",
    "credentials": {
      "token": "<github-pat>",
      "tenant_id": "<azure-tenant-id>",
      "client_id": "<azure-client-id>",
      "client_secret": "<azure-client-secret>",
      "subscription_id": "<azure-subscription-id>"
    }
  }
}
```

For `"source_control": "azure_devops"`, `credentials` should include
`organization`, `project`, and `token` instead.

### Response (immediate, async processing)
```json
{
  "workflow": "Static_Depth_for_Infrastructure",
  "status": "in_progress",
  "result": null,
  "error": null,
  "timestamp": "2026-07-10T10:00:00.000000"
}
```

### Final persisted result shape (fields per the spec's "Final Response Format")
```json
{
  "workflow": "Static_Depth_for_Infrastructure",
  "maturity_level": 1,
  "score": 0.5,
  "max_score": 5.0,
  "status": "FAIL",
  "level_wise_results": [ /* all 5 levels, PASSED / FAILED / NOT_CHECKED, with node_results */ ],
  "node_wise_results": [ {"level": 1, "node": "Test for Stored Secrets in Source Code", "status": "FAILED", "reason": "..."} ],
  "passed_checks": ["Level 1: Test for Stored Secrets in Build Artifacts"],
  "failed_checks": ["Level 1: Test for Stored Secrets in Source Code"],
  "evidence_collected": ["..."],
  "findings": ["..."],
  "reasoning": "...",
  "missing_controls": ["Level 1: Test for Stored Secrets in Source Code — No supporting evidence detected."],
  "security_risks": ["..."],
  "recommendations": [
    {"gap": "No secret scanning on source history", "action": "Add gitleaks to CI on every push", "priority": "high", "suggested_tools": ["Gitleaks", "TruffleHog"]}
  ],
  "next_maturity_level": 2,
  "summary": "Assessment stopped at Level 1 (Secrets Hygiene) — 1 control(s) failed. Maturity Level = 1."
}
```

## Maturity levels

| Level | Name                                                        | Score Range |
|-------|--------------------------------------------------------------|-------------|
| 1     | Secrets Hygiene                                               | 0.0 – 1.0   |
| 2     | Deployment, Runtime & Cloud Configuration Security             | 1.0 – 2.0   |
| 3     | Malware & Image Freshness                                     | 2.0 – 3.0   |
| 4     | Vulnerability Correlation & Software Composition Analysis      | 3.0 – 4.0   |
| 5     | Fully Mature (no additional controls currently defined)        | 4.0 – 5.0   |

A level passes only if **all** of its controls pass. On the first failed
level, the workflow stops immediately — higher levels are never evaluated.

## Controls by level

- **Level 1:** Test for Stored Secrets in Build Artifacts, Test for Stored Secrets in Source Code
- **Level 2:** Test Cluster Deployment Resources, Test Image Lifetime, Test Virtualized Environments, Test Cloud Configuration, Test Definition of Virtualized Environments
- **Level 3:** Test for Malware, Test for New Image Version
- **Level 4:** Correlate Known Vulnerabilities with New Image Versions, Software Composition Analysis (SCA), Test Infrastructure Components for Known Vulnerabilities
- **Level 5:** (none — always passes once reached)

## How evidence is collected

**Source control connectors** (`azure_devops.py`, `github.py`) collect CI/CD
pipeline YAML content and a flattened repository file listing (up to 500
files), then scan both against `SIGNAL_KEYWORDS` (defined once in
`azure_devops.py`, reused by `github.py`) — a dict mapping each of the 12
real criteria to keyword/filename indicators (secret scanners, IaC scanning
tools, Terraform/Bicep file presence, etc.).

**The Azure cloud connector** (`azure_cloud.py`) queries:
- `Microsoft.Security/pricings` — which Defender for Cloud plans are set to
  Standard tier, mapped to the criteria each plan provides evidence for
  (`DEFENDER_PLAN_SIGNALS`).
- Subscription resource listing — presence of AKS clusters
  (`Microsoft.ContainerService/managedClusters`) and container registries
  (`Microsoft.ContainerRegistry/registries`), mapped via
  `RESOURCE_TYPE_SIGNALS`.

Both are merged into `detected_signals` and handed to the LLM per level as
structured, provider-agnostic evidence — the LLM never sees raw provider API
responses.

## Adding a new provider

**Source control:** create `connectors/<platform>.py` implementing
`BaseSourceControlConnector`, reusing `_detect_signals` / `SIGNAL_KEYWORDS`
from `connectors/azure_devops.py` (as `connectors/github.py` does), then add
one entry to `SOURCE_CONTROL_CONNECTOR_REGISTRY` in `connectors/__init__.py`.

**Cloud:** create `connectors/<platform>_cloud.py` implementing
`BaseCloudConnector` (e.g. for AWS, GCP, Kubernetes, OpenShift), then add one
entry to `CLOUD_CONNECTOR_REGISTRY`.

No changes to `nodes.py`, `graph.py`, or `config.py` are needed to add a
provider. To add or change a *criterion*, update `LEVEL_CRITERIA_NAMES` in
`config.py`, the matching system prompt, and `SIGNAL_KEYWORDS` /
`DEFENDER_PLAN_SIGNALS` / `RESOURCE_TYPE_SIGNALS` together — they must stay
in sync or the evidence floor will incorrectly fail a criterion that has no
mapped detection logic.

## Files

```
workflows/Static_Depth_for_Infrastructure/
├── __init__.py
├── config.py              ← score ranges, level descriptions, criteria names, LLM prompts (with grounding instruction)
├── nodes.py                ← collect node + level1-4 nodes (LLM+evidence floor) + level5 (auto-pass) + format_result node
├── graph.py                ← InfrastructureDepthState TypedDict + StaticDepthForInfrastructureWorkflow
├── README.md
└── connectors/
    ├── __init__.py         ← SOURCE_CONTROL_CONNECTOR_REGISTRY / CLOUD_CONNECTOR_REGISTRY
    ├── base.py              ← ABCs + provider-agnostic dataclasses
    ├── azure_devops.py      ← SIGNAL_KEYWORDS defined here
    ├── github.py             ← reuses azure_devops.py's detection logic
    └── azure_cloud.py        ← DEFENDER_PLAN_SIGNALS + RESOURCE_TYPE_SIGNALS
```

## Assumptions

- `repository` is read from the top-level `input_data.repository` field. If
  omitted, it falls back to `credentials.repository` or `credentials.project`.
- `platform.cloud_provider` is the primary key (matching this backend's
  established convention); `platform.cloud` is accepted as a fallback.
- Because cloud evidence is central here, running without `cloud_provider`
  supplied will very likely stall at Level 2 (which has 3 of its 5 criteria
  primarily cloud-sourced) purely due to the evidence floor, not a real
  security gap — this is expected, not a bug.
- `security_risks` and `findings` come directly from the LLM's response per
  level (not independently re-derived), since these are inherently
  judgment/narrative fields rather than countable checks.
