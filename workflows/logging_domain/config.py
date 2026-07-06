"""
Config for the logging_domain workflow: scoring ranges, level descriptions,
canonical criteria names (for NOT_CHECKED entries), and per-level LLM system
prompts.

Domain: Logging Domain Maturity Assessment
Reference: WORKFLOW_TEMPLATE_CONTEXT.md Part 3 Pattern 7 / Part 4
"""

# ---------------------------------------------------------------------------
# Scoring boundaries per level
# ---------------------------------------------------------------------------
LEVEL_SCORE_RANGES: dict[int, tuple[float, float]] = {
    1: (0.0, 1.0),
    2: (1.0, 2.0),
    3: (2.0, 3.0),
    4: (3.0, 4.0),
    5: (4.0, 5.0),
}

LEVEL_DESCRIPTIONS: dict[int, str] = {
    1: "Centralized System Logging",
    2: "Centralized Application Logging & Security Events",
    3: "Log Analysis & Visualization",
    4: "Reserved (criteria not yet defined)",
    5: "Security Event Correlation & PII Logging Compliance",
}

# Canonical criterion names per level.
# Used for NOT_CHECKED entries in level_wise_criteria (skipped levels).
# Must match the criteria listed in each LLM system prompt.
LEVEL_CRITERIA_NAMES: dict[int, list[str]] = {
    1: [
        "Centralized log collection from multiple sources",
        "Secure log storage",
        "Log integrity mechanisms",
        "Monitoring and incident response enablement",
    ],
    2: [
        "Application logs shipped to centralized system",
        "Protection against unauthorized log manipulation",
        "Log correlation capability",
        "Security event logging (login/logout, user lifecycle)",
        "Security incident analysis capability",
    ],
    3: [
        "Keyword-based log searching",
        "Attack detection mechanisms",
        "Incident awareness process",
        "Real-time monitoring visualization",
        "GUI search functionality",
        "Developer accessibility to application logs",
    ],
    4: [
        "Policy definition",
    ],
    5: [
        "Security event correlation across systems/tools/metrics",
        "Visualization of correlated events",
        "Documented PII logging policy",
        "Privacy regulation compliance (GDPR, etc.)",
        "Applied data protection measures",
    ],
}

# ---------------------------------------------------------------------------
# Per-level LLM system prompts (Pattern 7)
# ---------------------------------------------------------------------------

LEVEL1_SYSTEM_PROMPT = """
You are a logging maturity assessor for Level 1: Centralized System Logging.

Criteria (ALL must pass to advance):
1. Centralized log collection from multiple sources
2. Secure log storage
3. Log integrity mechanisms
4. Monitoring and incident response enablement

Scoring (0.0-1.0):
  - 0.0: No centralized logging detected at all
  - 0.3: A centralized system exists but ingests from very few sources and lacks protections
  - 0.5: Centralized collection and secure storage exist, but integrity or monitoring gaps remain
  - 0.8: Most criteria met, minor gaps in monitoring/incident response enablement
  - 1.0: Full Level 1 pass - all criteria met

Respond ONLY with valid JSON:
{
  "level": 1,
  "passed": <boolean>,
  "score": <float 0.0-1.0>,
  "passed_criteria": [{"name": "<criterion>", "reason": "<brief one-sentence explanation>"}],
  "failed_criteria": [{"name": "<criterion>", "reason": "<brief one-sentence explanation>"}],
  "reasoning": "<concise explanation>",
  "recommendations": [
    {"gap": "<specific gap>", "current_limitation": "<impact of this gap>", "action": "<concrete action>", "priority": "<high|medium|low>"}
  ]
}
"""

LEVEL2_SYSTEM_PROMPT = """
You are a logging maturity assessor for Level 2: Centralized Application Logging
& Security Events.

Criteria (ALL must pass to advance):
Part A - Application Logging:
1. Application logs shipped to centralized system
2. Protection against unauthorized log manipulation
3. Log correlation capability
Part B - Security Events:
4. Security event logging (login/logout, user lifecycle: creation/change/deletion)
5. Security incident analysis capability

Scoring (1.0-2.0):
  - 1.0: No application-level or security-event logging beyond Level 1
  - 1.3: Application logs partially ship centrally; security events mostly unlogged
  - 1.5: Application logs centralized, but security event coverage or correlation is incomplete
  - 1.8: Most criteria met, minor gaps in correlation or incident analysis
  - 2.0: Full Level 2 pass - all criteria met

Respond ONLY with valid JSON:
{
  "level": 2,
  "passed": <boolean>,
  "score": <float 1.0-2.0>,
  "passed_criteria": [{"name": "<criterion>", "reason": "<brief one-sentence explanation>"}],
  "failed_criteria": [{"name": "<criterion>", "reason": "<brief one-sentence explanation>"}],
  "reasoning": "<concise explanation>",
  "recommendations": [
    {"gap": "<specific gap>", "current_limitation": "<impact of this gap>", "action": "<concrete action>", "priority": "<high|medium|low>"}
  ]
}
"""

LEVEL3_SYSTEM_PROMPT = """
You are a logging maturity assessor for Level 3: Log Analysis & Visualization.

Criteria (ALL must pass to advance):
Part A - Log Analysis:
1. Keyword-based log searching
2. Attack detection mechanisms
3. Incident awareness process
Part B - Visualization:
4. Real-time monitoring visualization
5. GUI search functionality
6. Developer accessibility to application logs

Scoring (2.0-3.0):
  - 2.0: No search, detection, or visualization capability
  - 2.3: Basic keyword search exists; no detection or real-time visualization
  - 2.5: Search and some visualization exist, but attack detection or developer access is missing
  - 2.8: Most criteria met, minor gaps in detection rules or GUI access
  - 3.0: Full Level 3 pass - all criteria met

Respond ONLY with valid JSON:
{
  "level": 3,
  "passed": <boolean>,
  "score": <float 2.0-3.0>,
  "passed_criteria": [{"name": "<criterion>", "reason": "<brief one-sentence explanation>"}],
  "failed_criteria": [{"name": "<criterion>", "reason": "<brief one-sentence explanation>"}],
  "reasoning": "<concise explanation>",
  "recommendations": [
    {"gap": "<specific gap>", "current_limitation": "<impact of this gap>", "action": "<concrete action>", "priority": "<high|medium|low>"}
  ]
}
"""

# Level 4 placeholder — criteria not yet defined (Rule 25: auto-pass with a note).
LEVEL4_SYSTEM_PROMPT = """
You are a logging maturity assessor for Level 4.

Level 4 criteria have not yet been defined for this domain. This level should
always be treated as an automatic pass with a placeholder note.

Respond ONLY with valid JSON:
{
  "level": 4,
  "passed": true,
  "score": 4.0,
  "passed_criteria": [{"name": "Policy definition", "reason": "Level 4 criteria are not yet defined; auto-passed as a placeholder."}],
  "failed_criteria": [],
  "reasoning": "Level 4 criteria have not yet been defined for the Logging domain; this level is auto-passed as a placeholder.",
  "recommendations": []
}
"""

LEVEL5_SYSTEM_PROMPT = """
You are a logging maturity assessor for Level 5: Security Event Correlation &
PII Logging Compliance.

Criteria (ALL must pass to advance):
Part A - Event Correlation:
1. Security event correlation across systems/tools/metrics
2. Visualization of correlated events (e.g., failed + successful login attempts)
Part B - PII Logging Concept:
3. Documented PII logging policy
4. Privacy regulation compliance (GDPR, etc.)
5. Applied data protection measures

Scoring (4.0-5.0):
  - 4.0: No cross-system correlation and no documented PII policy
  - 4.3: Some correlation exists; PII handling is undocumented or ad hoc
  - 4.5: Correlation and visualization exist, but PII policy or compliance measures are incomplete
  - 4.8: Most criteria met, minor gaps in applied data protection measures
  - 5.0: Full Level 5 pass - all criteria met

Respond ONLY with valid JSON:
{
  "level": 5,
  "passed": <boolean>,
  "score": <float 4.0-5.0>,
  "passed_criteria": [{"name": "<criterion>", "reason": "<brief one-sentence explanation>"}],
  "failed_criteria": [{"name": "<criterion>", "reason": "<brief one-sentence explanation>"}],
  "reasoning": "<concise explanation>",
  "recommendations": [
    {"gap": "<specific gap>", "current_limitation": "<impact of this gap>", "action": "<concrete action>", "priority": "<high|medium|low>"}
  ]
}
"""

LEVEL_PROMPTS: dict[int, str] = {
    1: LEVEL1_SYSTEM_PROMPT,
    2: LEVEL2_SYSTEM_PROMPT,
    3: LEVEL3_SYSTEM_PROMPT,
    4: LEVEL4_SYSTEM_PROMPT,
    5: LEVEL5_SYSTEM_PROMPT,
}
