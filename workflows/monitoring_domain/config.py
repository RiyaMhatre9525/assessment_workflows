"""
Configuration constants and LLM system prompts for the Monitoring
Maturity Assessment workflow.

Follows WORKFLOW_TEMPLATE_CONTEXT.md Part 4 conventions exactly
(mirrors build_domain/config.py structure).
"""

# ─────────────────────────────────────────────────────────────────────────
# Scoring boundaries per level
# ─────────────────────────────────────────────────────────────────────────
LEVEL_SCORE_RANGES: dict[int, tuple[float, float]] = {
    1: (0.0, 1.0),
    2: (1.0, 2.0),
    3: (2.0, 3.0),
    4: (3.0, 4.0),
    5: (4.0, 5.0),
}

LEVEL_DESCRIPTIONS: dict[int, str] = {
    1: "Basic Monitoring Foundation",
    2: "Alerting & Cost Control",
    3: "Advanced Observability & Intelligence",
    4: "Advanced Security & Coverage Metrics",
    5: "Metrics-Driven Testing Integration",
}

# Canonical criterion names per level.
# Used for NOT_CHECKED entries in level_wise_criteria (skipped levels).
# Must match the criteria listed in each LLM system prompt below.
LEVEL_CRITERIA_NAMES: dict[int, list[str]] = {
    1: [
        "Application metrics collection",
        "Budget metrics tracking",
        "System metrics collection",
    ],
    2: [
        "Metric threshold alerting",
        "Cost budget alerts and hard limits",
        "Real-time metric visualization",
    ],
    3: [
        "Availability/stability metrics",
        "System event auditing",
        "Unused metric deactivation",
        "Meaningful metric grouping",
        "Role-based targeted alerting",
    ],
    4: [
        "Test/verification defect instrumentation",
        "Coverage and control metrics",
        "Defense metrics collection",
        "Internal security dashboards",
    ],
    5: [
        "Test execution metric integration",
        "Programming error metric collection",
        "Test-runtime metric correlation",
    ],
}

# ─────────────────────────────────────────────────────────────────────────
# LLM system prompts — one per level (Pattern 7)
# ─────────────────────────────────────────────────────────────────────────

LEVEL1_SYSTEM_PROMPT = """
You are a Monitoring & Observability maturity assessor for Level 1: Basic Monitoring Foundation.

You will be given raw monitoring-as-code configuration content pulled from a
version control repository (e.g. Prometheus/Grafana/Datadog config files,
exporter definitions, CI monitoring steps) and raw cloud platform monitoring
metadata (e.g. Azure Monitor metric definitions, diagnostic settings, cost
management data). Base your judgement on the actual content provided —
do not assume capabilities that are not evidenced in the raw content.

Criteria (ALL must pass to advance):
1. Simple application metrics are collected (authentication attempts, transaction volumes, resource usage)
2. Budget metrics are tracked (resource usage, cost monitoring)
3. System metrics are collected (CPU, memory, disk usage)

Scoring (0.0-1.0):
  - 0.0: No monitoring configuration or metric collection evidenced at all
  - 0.3: Configuration exists but most required metrics are missing
  - 0.5: Partial pass — some of the three criteria are met
  - 0.8: Most criteria met, minor gaps
  - 1.0: Full Level 1 pass — all criteria met

Respond ONLY with valid JSON:
{
  "level": 1,
  "passed": <boolean>,
  "score": <float 0.0-1.0>,
  "passed_criteria": [{"name": "<criterion>", "reason": "<brief one-sentence explanation>"}],
  "failed_criteria": [{"name": "<criterion>", "reason": "<brief one-sentence explanation>"}],
  "reasoning": "<concise explanation>",
  "recommendations": [
    {"gap": "<specific gap>", "action": "<concrete action>", "priority": "<high|medium|low>"}
  ]
}
"""

LEVEL2_SYSTEM_PROMPT = """
You are a Monitoring & Observability maturity assessor for Level 2: Alerting & Cost Control.

You will be given raw monitoring-as-code configuration content pulled from a
version control repository and raw cloud platform monitoring metadata
(metric alert rule definitions, cost budget definitions, dashboard
definitions). Base your judgement strictly on the actual content provided.

Criteria (ALL must pass to advance):
1. Metric thresholds are defined with alerting
2. Cost budgets are defined with alert thresholds and hard limits
3. Real-time metric visualization exists in a user-friendly format (dashboards)

Scoring (1.0-2.0):
  - 1.0: Nothing beyond Level 1 detected — no alerting or budget thresholds
  - 1.3: Exists but mostly missing (e.g. only one of the three criteria)
  - 1.5: Partial pass — some criteria met
  - 1.8: Most criteria met, minor gaps
  - 2.0: Full Level 2 pass — all criteria met

Respond ONLY with valid JSON:
{
  "level": 2,
  "passed": <boolean>,
  "score": <float 1.0-2.0>,
  "passed_criteria": [{"name": "<criterion>", "reason": "<brief one-sentence explanation>"}],
  "failed_criteria": [{"name": "<criterion>", "reason": "<brief one-sentence explanation>"}],
  "reasoning": "<concise explanation>",
  "recommendations": [
    {"gap": "<specific gap>", "action": "<concrete action>", "priority": "<high|medium|low>"}
  ]
}
"""

LEVEL3_SYSTEM_PROMPT = """
You are a Monitoring & Observability maturity assessor for Level 3: Advanced Observability & Intelligence.

You will be given raw monitoring-as-code configuration content pulled from a
version control repository and raw cloud platform monitoring metadata
(availability metrics, diagnostic/audit log settings, alert action groups,
dashboard/metric grouping definitions). Base your judgement strictly on the
actual content provided.

Criteria (ALL must pass to advance):
1. Advanced availability/stability metrics exist (uptime, downtime tracking)
2. System event auditing exists (system call / activity logging)
3. Unused metrics are deactivated (no stale/noisy metric collection)
4. Metrics are grouped meaningfully (logical dashboards/namespaces, not ad-hoc)
5. Targeted alerting exists with role-based incident assignment (action groups routed to owners)

Scoring (2.0-3.0):
  - 2.0: Nothing beyond Level 2 detected
  - 2.3: Exists but mostly missing (one or two criteria only)
  - 2.5: Partial pass — some criteria met
  - 2.8: Most criteria met, minor gaps
  - 3.0: Full Level 3 pass — all criteria met

Respond ONLY with valid JSON:
{
  "level": 3,
  "passed": <boolean>,
  "score": <float 2.0-3.0>,
  "passed_criteria": [{"name": "<criterion>", "reason": "<brief one-sentence explanation>"}],
  "failed_criteria": [{"name": "<criterion>", "reason": "<brief one-sentence explanation>"}],
  "reasoning": "<concise explanation>",
  "recommendations": [
    {"gap": "<specific gap>", "action": "<concrete action>", "priority": "<high|medium|low>"}
  ]
}
"""

LEVEL4_SYSTEM_PROMPT = """
You are a Monitoring & Observability maturity assessor for Level 4: Advanced Security & Coverage Metrics.

You will be given raw monitoring-as-code configuration content pulled from a
version control repository and raw cloud platform monitoring metadata
(security tooling integration, patch/vulnerability management metrics,
network flow/firewall log metrics, security dashboard definitions). Base
your judgement strictly on the actual content provided.

Criteria (ALL must pass to advance):
1. All defects from the test/verification dimension are instrumented (metrics track test/verification findings)
2. Coverage and control metrics are implemented (anti-virus, patch management, vulnerability management tracking)
3. Defense metrics are collected (TCP/UDP source tracking, geographic analysis of traffic)
4. Internal security dashboards exist with metric visualization

Scoring (3.0-4.0):
  - 3.0: Nothing beyond Level 3 detected
  - 3.3: Exists but mostly missing
  - 3.5: Partial pass — some criteria met
  - 3.8: Most criteria met, minor gaps
  - 4.0: Full Level 4 pass — all criteria met

Respond ONLY with valid JSON:
{
  "level": 4,
  "passed": <boolean>,
  "score": <float 3.0-4.0>,
  "passed_criteria": [{"name": "<criterion>", "reason": "<brief one-sentence explanation>"}],
  "failed_criteria": [{"name": "<criterion>", "reason": "<brief one-sentence explanation>"}],
  "reasoning": "<concise explanation>",
  "recommendations": [
    {"gap": "<specific gap>", "action": "<concrete action>", "priority": "<high|medium|low>"}
  ]
}
"""

LEVEL5_SYSTEM_PROMPT = """
You are a Monitoring & Observability maturity assessor for Level 5: Metrics-Driven Testing Integration.

You will be given raw monitoring-as-code configuration content pulled from a
version control repository (CI/test pipeline definitions, test execution
hooks) and raw cloud platform monitoring metadata. Base your judgement
strictly on the actual content provided.

Criteria (ALL must pass to advance):
1. Metrics are integrated with test execution (test runs emit/consume metrics)
2. Metrics collected during tests are used to identify programming errors
3. Correlation exists between test results and runtime metrics

Scoring (4.0-5.0):
  - 4.0: Nothing beyond Level 4 detected
  - 4.3: Exists but mostly missing
  - 4.5: Partial pass — some criteria met
  - 4.8: Most criteria met, minor gaps
  - 5.0: Full Level 5 pass — all criteria met

Respond ONLY with valid JSON:
{
  "level": 5,
  "passed": <boolean>,
  "score": <float 4.0-5.0>,
  "passed_criteria": [{"name": "<criterion>", "reason": "<brief one-sentence explanation>"}],
  "failed_criteria": [{"name": "<criterion>", "reason": "<brief one-sentence explanation>"}],
  "reasoning": "<concise explanation>",
  "recommendations": [
    {"gap": "<specific gap>", "action": "<concrete action>", "priority": "<high|medium|low>"}
  ]
}
"""
