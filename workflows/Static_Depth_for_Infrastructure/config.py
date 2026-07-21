"""
Configuration constants for the Static_Depth_for_Infrastructure workflow:
scoring ranges, level descriptions, canonical criteria names, and the LLM
system prompt used to assess each level's controls.
 
Unlike the application-focused workflows in this backend, Level 1 here has
real controls (no baseline "N/A" level), and Level 5 has NO defined controls
per the spec — it always passes once every prior level has fully passed, so
it has no system prompt.
"""
 
LEVEL_SCORE_RANGES: dict[int, tuple[float, float]] = {
    1: (0.0, 1.0),
    2: (1.0, 2.0),
    3: (2.0, 3.0),
    4: (3.0, 4.0),
    5: (4.0, 5.0),
}
 
LEVEL_DESCRIPTIONS: dict[int, str] = {
    1: "Secrets Hygiene",
    2: "Deployment, Runtime & Cloud Configuration Security",
    3: "Malware & Image Freshness",
    4: "Vulnerability Correlation & Software Composition Analysis",
    5: "Fully Mature (no additional controls defined)",
}
 
# Canonical criterion names per level.
# Used for NOT_CHECKED entries in level_wise_criteria (skipped levels) and
# must match the criteria listed in each level's LLM system prompt AND the
# SIGNAL_KEYWORDS keys used by the connectors.
LEVEL_CRITERIA_NAMES: dict[int, list[str]] = {
    1: [
        "Test for Stored Secrets in Build Artifacts",
        "Test for Stored Secrets in Source Code",
    ],
    2: [
        "Test Cluster Deployment Resources",
        "Test Image Lifetime",
        "Test Virtualized Environments",
        "Test Cloud Configuration",
        "Test Definition of Virtualized Environments",
    ],
    3: [
        "Test for Malware",
        "Test for New Image Version",
    ],
    4: [
        "Correlate Known Vulnerabilities with New Image Versions",
        "Software Composition Analysis (SCA)",
        "Test Infrastructure Components for Known Vulnerabilities",
    ],
    5: [],  # No controls defined — always passes once reached.
}
 
_JSON_SCHEMA_SUFFIX = """
IMPORTANT — Evidence grounding rule:
Only mark a criterion as PASSED if the evidence summary below explicitly
shows a matched signal, tool, file, or resource that supports it. If the
evidence for a criterion is empty or absent, you MUST place it in
failed_criteria with the reason "No supporting evidence detected." Do not
infer a pass from general repository/pipeline health, file counts, or the
mere existence of the repository — only from concrete matched evidence.
 
Respond ONLY with valid JSON:
{{
  "level": {level},
  "passed": <boolean>,
  "score": <float {min_score}-{max_score}>,
  "passed_criteria": [{{"name": "<criterion>", "reason": "<cite the specific evidence observed>"}}],
  "failed_criteria": [{{"name": "<criterion>", "reason": "<brief one-sentence explanation>"}}],
  "reasoning": "<concise explanation>",
  "evidence": ["<specific evidence item observed>", "..."],
  "findings": ["<specific finding, positive or negative>", "..."],
  "security_risks": ["<specific security risk implied by a failed criterion>", "..."],
  "recommendations": [
    {{"gap": "<specific gap>", "action": "<concrete action>", "priority": "<high|medium|low>", "suggested_tools": ["<tool name>", "..."]}}
  ]
}}
"""
 
LEVEL1_SYSTEM_PROMPT = """
You are an infrastructure security maturity assessor for Level 1: Secrets
Hygiene.
 
Criteria (ALL must pass to advance):
1. Test for Stored Secrets in Build Artifacts — no secrets (API keys,
   passwords, tokens, certificates, SSH keys) are found in container images,
   build artifacts, packages, or archives. Evidence of active secret
   scanning tooling against build outputs counts as passing.
2. Test for Stored Secrets in Source Code — no hardcoded secrets exist in
   source code, commit history, or Git history. Evidence of active secret
   scanning tooling against source code/history counts as passing.
 
Scoring (0.0-1.0):
  0.0: Neither criterion met.
  0.5: One of the two criteria met.
  1.0: Full Level 1 pass — both criteria met.
""" + _JSON_SCHEMA_SUFFIX.format(level=1, min_score="0.0", max_score="1.0")
 
LEVEL2_SYSTEM_PROMPT = """
You are an infrastructure security maturity assessor for Level 2:
Deployment, Runtime & Cloud Configuration Security.
 
Criteria (ALL must pass to advance):
1. Test Cluster Deployment Resources — deployment configurations
   (Kubernetes, AKS, deployment manifests, Helm charts) are validated for
   insecure settings.
2. Test Image Lifetime — container image age is checked against an
   organization-defined maximum allowed lifetime.
3. Test Virtualized Environments — VM/container runtime configurations
   (networking, security policies) are analyzed for insecure settings.
4. Test Cloud Configuration — cloud configuration (IAM, networking, storage,
   encryption, identity) is validated using cloud provider APIs/security
   best practices (e.g. Microsoft Defender for Cloud, Azure Policy).
5. Test Definition of Virtualized Environments — Infrastructure as Code
   (ARM templates, Terraform, Bicep, Kubernetes YAML) is analyzed for
   insecure definitions.
 
Scoring (1.0-2.0):
  1.0: 0 of 5 criteria met.
  Proportional score for 1-4 of 5 criteria met.
  2.0: Full Level 2 pass — all five criteria met.
""" + _JSON_SCHEMA_SUFFIX.format(level=2, min_score="1.0", max_score="2.0")
 
LEVEL3_SYSTEM_PROMPT = """
You are an infrastructure security maturity assessor for Level 3: Malware &
Image Freshness.
 
Criteria (ALL must pass to advance):
1. Test for Malware — container images, VM images, libraries, and
   infrastructure components are scanned for malware or malicious
   components.
2. Test for New Image Version — the pipeline/tooling determines whether
newer container base images are available (e.g. Ubuntu, Alpine, NGINX,
.NET runtime, Node runtime).
 
Evidence that satisfies this criterion includes tools or pipeline steps
such as Renovate, Dependabot, Docker Scout, Base Image Update checks,
image update automation, or any automated mechanism that detects newer
container base image versions. If such evidence is present, this
criterion MUST be marked as PASSED.
 
IMPORTANT:
Do not fail a criterion if matching evidence already exists in the
Evidence section. The detected evidence is authoritative.
The evidence list may contain terms such as "renovate",
"base image update", "docker scout", or "dependabot".
Treat these as valid evidence for "Test for New Image Version".
 
Scoring (2.0-3.0):
  2.0: Neither criterion met.
  2.5: Only one of the two criteria met.
  3.0: Full Level 3 pass — both criteria met.
""" + _JSON_SCHEMA_SUFFIX.format(level=3, min_score="2.0", max_score="3.0")
 
LEVEL4_SYSTEM_PROMPT = """
You are an infrastructure security maturity assessor for Level 4:
Vulnerability Correlation & Software Composition Analysis.
 
Criteria (ALL must pass to advance):
1. Correlate Known Vulnerabilities with New Image Versions — there is
   evidence that upgrading to newer images is evaluated for whether it
   mitigates known vulnerabilities (not just that newer images exist).
2. Software Composition Analysis (SCA) — infrastructure-related dependencies
   (OS packages, libraries) are scanned for known vulnerabilities.
3. Test Infrastructure Components for Known Vulnerabilities — operating
   system packages, VM images, container images, and infrastructure
   components are scanned to identify CVEs, security advisories, or missing
   security updates.
 
Scoring (3.0-4.0):
  3.0: 0 of 3 criteria met.
  3.33 / 3.67: proportional to 1 or 2 of 3 criteria met.
  4.0: Full Level 4 pass — all three criteria met.
""" + _JSON_SCHEMA_SUFFIX.format(level=4, min_score="3.0", max_score="4.0")
 
 