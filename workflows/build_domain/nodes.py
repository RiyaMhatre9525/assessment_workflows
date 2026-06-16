"""
Assessment nodes for the Pipeline Maturity workflow.

Each node corresponds to one maturity level.  Nodes follow the fail-fast
pattern: if an assessment fails, they set `stop_assessment = True` in the
state so the graph router skips all subsequent levels.

Node signature: async def node(state: dict) -> dict
  - Reads from state
  - Returns only the keys it modified (LangGraph merges)
"""

from __future__ import annotations

import json
import re

from core.logger import get_logger
from core.llm_provider import LLMProvider
from workflows.build_domain.config import (
    LEVEL1_SYSTEM_PROMPT,
    LEVEL2_SYSTEM_PROMPT,
    LEVEL3_SYSTEM_PROMPT,
    LEVEL5_SYSTEM_PROMPT,
    LEVEL_SCORE_RANGES,
    SBOM_TOOLS,
)
from workflows.build_domain.connectors.base import PlatformData

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _call_llm(system_prompt: str, user_content: str) -> dict:
    """
    Synchronous LLM call (used inside async node via awaited wrapper).

    Returns the parsed JSON dict from the model, or an error dict.
    """
    llm = LLMProvider().get_llm()
    from langchain_core.messages import HumanMessage, SystemMessage

    try:
        response = llm.invoke(
            [
                SystemMessage(content=system_prompt),
                HumanMessage(content=user_content),
            ]
        )
        raw = response.content.strip()
        # Strip markdown fences if present
        raw = re.sub(r"^```(?:json)?\s*", "", raw)
        raw = re.sub(r"\s*```$", "", raw)
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        logger.error("LLM returned non-JSON: %s – %s", exc, response.content[:200])
        return {"error": f"JSON parse error: {exc}", "raw": response.content}
    except Exception as exc:
        logger.error("LLM call failed: %s", exc)
        return {"error": str(exc)}


async def _async_llm(system_prompt: str, user_content: str) -> dict:
    """Async wrapper around the synchronous LLM call."""
    llm = LLMProvider().get_llm()
    from langchain_core.messages import HumanMessage, SystemMessage

    try:
        response = await llm.ainvoke(
            [
                SystemMessage(content=system_prompt),
                HumanMessage(content=user_content),
            ]
        )
        raw = response.content.strip()
        raw = re.sub(r"^```(?:json)?\s*", "", raw)
        raw = re.sub(r"\s*```$", "", raw)
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        logger.error("LLM returned non-JSON: %s", exc)
        return {"error": f"JSON parse error: {exc}"}
    except Exception as exc:
        logger.error("LLM call failed: %s", exc)
        return {"error": str(exc)}


def _platform_data_summary(pd: PlatformData) -> str:
    """Serialise PlatformData into a compact string for the LLM context."""
    return json.dumps(
        {
            "platform_type": pd.platform_type,
            "repository": pd.repository,
            "pipelines": [
                {
                    "name": p.name,
                    "path": p.path,
                    "has_build_job": p.has_build_job,
                    "has_test_job": p.has_test_job,
                    "has_security_scan_job": p.has_security_scan_job,
                    "content_snippet": p.raw_content[:800],
                }
                for p in pd.pipelines
            ],
            "artifacts": [
                {
                    "name": a.name,
                    "tag": a.tag,
                    "digest": a.digest,
                    "immutability_enforced": a.immutability_enforced,
                    "sbom_detected": a.sbom_detected,
                    "sbom_tool": a.sbom_tool,
                }
                for a in pd.artifacts
            ],
            "commit_signing": {
                "total_commits_checked": pd.commit_signing.total_commits_checked,
                "signed_commits": pd.commit_signing.signed_commits,
                "unsigned_commits": pd.commit_signing.unsigned_commits,
                "branch_protection_enforced": pd.commit_signing.branch_protection_enforced,
                "required_signed_commits_policy": pd.commit_signing.required_signed_commits_policy,
            },
            "artifact_signing": {
                "signing_tool_detected": pd.artifact_signing.signing_tool_detected,
                "all_artifacts_signed": pd.artifact_signing.all_artifacts_signed,
                "signature_verification_in_deployment": (
                    pd.artifact_signing.signature_verification_in_deployment
                ),
            },
        },
        indent=2,
    )


# ---------------------------------------------------------------------------
# Node: data collection
# ---------------------------------------------------------------------------

async def collect_platform_data_node(state: dict) -> dict:
    """
    Node 0: Authenticate against the target platform and collect raw data.

    Reads:
        state["platform_type"]  – e.g. "github", "azure_devops"
        state["credentials"]    – auth dict
        state["repository"]     – "owner/repo" or "project/repo"

    Writes:
        state["platform_data"]  – PlatformData object
        state["status"]
    """
    logger.info("── collect_platform_data_node: START ──")

    from workflows.build_domain.connectors import CONNECTOR_REGISTRY

    platform_type: str = state.get("platform_type", "").lower()
    credentials: dict = state.get("credentials", {})
    repository: str = state.get("repository", "")

    # Resolve connector
    connector_cls = CONNECTOR_REGISTRY.get(platform_type)
    if not connector_cls:
        supported = ", ".join(CONNECTOR_REGISTRY.keys())
        logger.error("Unknown platform_type: %s. Supported: %s", platform_type, supported)
        return {
            "status": "error",
            "error_message": f"Unsupported platform '{platform_type}'. Supported: {supported}",
            "stop_assessment": True,
        }

    connector = connector_cls(credentials)

    # Health check
    healthy = await connector.health_check()
    if not healthy:
        logger.error("Platform health check failed for %s", platform_type)
        return {
            "status": "error",
            "error_message": "Platform credentials invalid or platform unreachable.",
            "stop_assessment": True,
        }

    # Collect data
    try:
        platform_data: PlatformData = await connector.collect(repository)
        logger.info(
            "Collected: %d pipelines, %d artifacts from %s",
            len(platform_data.pipelines),
            len(platform_data.artifacts),
            platform_type,
        )
    except Exception as exc:
        logger.error("Data collection failed: %s", exc, exc_info=True)
        return {
            "status": "error",
            "error_message": f"Data collection error: {exc}",
            "stop_assessment": True,
        }

    # Enrich SBOM detection from pipeline content
    for artifact in platform_data.artifacts:
        combined = "\n".join(p.raw_content for p in platform_data.pipelines)
        for tool in SBOM_TOOLS:
            if re.search(re.escape(tool), combined, re.I):
                artifact.sbom_detected = True
                artifact.sbom_tool = tool
                break

    return {
        "platform_data": platform_data,
        "status": "data_collected",
        "stop_assessment": False,
    }


# ---------------------------------------------------------------------------
# Node: Level 1 assessment
# ---------------------------------------------------------------------------

async def level1_node(state: dict) -> dict:
    """
    Node 1: Assess Build Process Definition (Level 1).

    Reads:
        state["platform_data"]
        state["stop_assessment"]

    Writes:
        state["level_results"][1]
        state["current_level"]
        state["stop_assessment"]
        state["final_score"]  (if stopping)
        state["status"]
    """
    logger.info("── level1_node: START ──")

    if state.get("stop_assessment"):
        logger.info("level1_node: skipping (stop_assessment=True)")
        return {}

    platform_data: PlatformData = state["platform_data"]
    summary = _platform_data_summary(platform_data)

    result = await _async_llm(
        system_prompt=LEVEL1_SYSTEM_PROMPT,
        user_content=f"Assess the following platform data for Level 1 criteria:\n\n{summary}",
    )

    if "error" in result:
        return {"status": "error", "error_message": result["error"], "stop_assessment": True}

    level_results = dict(state.get("level_results", {}))
    level_results[1] = result

    passed = result.get("passed", False)
    score = result.get("score", 0.0)

    logger.info("Level 1 assessment: passed=%s score=%.2f", passed, score)

    if not passed:
        logger.info("Level 1 FAILED – stopping assessment")
        return {
            "level_results": level_results,
            "current_level": 1,
            "final_score": score,
            "stop_assessment": True,
            "status": "assessment_stopped_at_level_1",
        }

    return {
        "level_results": level_results,
        "current_level": 1,
        "status": "level_1_passed",
        "stop_assessment": False,
    }


# ---------------------------------------------------------------------------
# Node: Level 2 assessment
# ---------------------------------------------------------------------------

async def level2_node(state: dict) -> dict:
    """
    Node 2: Assess Artifact Pinning & SBOM (Level 2).
    """
    logger.info("── level2_node: START ──")

    if state.get("stop_assessment"):
        logger.info("level2_node: skipping (stop_assessment=True)")
        return {}

    platform_data: PlatformData = state["platform_data"]
    summary = _platform_data_summary(platform_data)

    result = await _async_llm(
        system_prompt=LEVEL2_SYSTEM_PROMPT,
        user_content=f"Assess the following platform data for Level 2 criteria:\n\n{summary}",
    )

    if "error" in result:
        return {"status": "error", "error_message": result["error"], "stop_assessment": True}

    level_results = dict(state.get("level_results", {}))
    level_results[2] = result

    passed = result.get("passed", False)
    score = result.get("score", 1.0)

    logger.info("Level 2 assessment: passed=%s score=%.2f", passed, score)

    if not passed:
        logger.info("Level 2 FAILED – stopping assessment")
        return {
            "level_results": level_results,
            "current_level": 2,
            "final_score": score,
            "stop_assessment": True,
            "status": "assessment_stopped_at_level_2",
        }

    return {
        "level_results": level_results,
        "current_level": 2,
        "status": "level_2_passed",
        "stop_assessment": False,
    }


# ---------------------------------------------------------------------------
# Node: Level 3 assessment
# ---------------------------------------------------------------------------

async def level3_node(state: dict) -> dict:
    """
    Node 3: Assess Code Signing & Enforcement (Level 3).
    """
    logger.info("── level3_node: START ──")

    if state.get("stop_assessment"):
        logger.info("level3_node: skipping (stop_assessment=True)")
        return {}

    platform_data: PlatformData = state["platform_data"]
    summary = _platform_data_summary(platform_data)

    result = await _async_llm(
        system_prompt=LEVEL3_SYSTEM_PROMPT,
        user_content=f"Assess the following platform data for Level 3 criteria:\n\n{summary}",
    )

    if "error" in result:
        return {"status": "error", "error_message": result["error"], "stop_assessment": True}

    level_results = dict(state.get("level_results", {}))
    level_results[3] = result

    passed = result.get("passed", False)
    score = result.get("score", 2.0)

    logger.info("Level 3 assessment: passed=%s score=%.2f", passed, score)

    if not passed:
        logger.info("Level 3 FAILED – stopping assessment")
        return {
            "level_results": level_results,
            "current_level": 3,
            "final_score": score,
            "stop_assessment": True,
            "status": "assessment_stopped_at_level_3",
        }

    return {
        "level_results": level_results,
        "current_level": 3,
        "status": "level_3_passed",
        "stop_assessment": False,
    }


# ---------------------------------------------------------------------------
# Node: Level 4 — placeholder
# ---------------------------------------------------------------------------

async def level4_node(state: dict) -> dict:
    """
    Node 4: Supply-Chain Policy — criteria TBD.

    Currently auto-passes so the workflow can reach Level 5.
    Replace the body with real assessment logic when criteria are defined.
    """
    logger.info("── level4_node: START (placeholder – auto-pass) ──")

    if state.get("stop_assessment"):
        logger.info("level4_node: skipping (stop_assessment=True)")
        return {}

    level_results = dict(state.get("level_results", {}))
    level_results[4] = {
        "level": 4,
        "passed": True,
        "score": 4.0,
        "passed_criteria": ["Placeholder — criteria not yet defined"],
        "failed_criteria": [],
        "reasoning": "Level 4 criteria are pending definition. Auto-passing to allow Level 5 assessment.",
        "recommendations": [
            {
                "gap": "Level 4 criteria undefined",
                "action": "Define supply-chain policy requirements and implement assessment logic.",
                "priority": "high",
            }
        ],
    }

    return {
        "level_results": level_results,
        "current_level": 4,
        "status": "level_4_passed",
        "stop_assessment": False,
    }


# ---------------------------------------------------------------------------
# Node: Level 5 assessment
# ---------------------------------------------------------------------------

async def level5_node(state: dict) -> dict:
    """
    Node 5: Assess Artifact Signing & Integrity (Level 5).
    """
    logger.info("── level5_node: START ──")

    if state.get("stop_assessment"):
        logger.info("level5_node: skipping (stop_assessment=True)")
        return {}

    platform_data: PlatformData = state["platform_data"]
    summary = _platform_data_summary(platform_data)

    result = await _async_llm(
        system_prompt=LEVEL5_SYSTEM_PROMPT,
        user_content=f"Assess the following platform data for Level 5 criteria:\n\n{summary}",
    )

    if "error" in result:
        return {"status": "error", "error_message": result["error"], "stop_assessment": True}

    level_results = dict(state.get("level_results", {}))
    level_results[5] = result

    passed = result.get("passed", False)
    score = result.get("score", 4.0)

    logger.info("Level 5 assessment: passed=%s score=%.2f", passed, score)

    return {
        "level_results": level_results,
        "current_level": 5,
        "final_score": score,
        "stop_assessment": True,   # always terminal
        "status": "level_5_completed",
    }


# ---------------------------------------------------------------------------
# Node: result formatting
# ---------------------------------------------------------------------------

async def format_result_node(state: dict) -> dict:
    """
    Terminal node: build the final structured result dict.

    Reads:
        state["level_results"]
        state["current_level"]
        state["final_score"]
        state["error_message"]  (optional)
        state["platform_data"]

    Writes:
        state["final_result"]
        state["status"]
    """
    logger.info("── format_result_node: START ──")

    error = state.get("error_message")
    if error:
        return {
            "final_result": {
                "maturity_level": 0,
                "score": 0.0,
                "score_range": "N/A",
                "assessment_details": {
                    "passed_criteria": [],
                    "failed_criteria": ["Platform connection or data collection failed"],
                    "reasoning": error,
                },
                "improvement_recommendations": [
                    {
                        "gap": "Platform connectivity",
                        "action": "Verify credentials and platform availability.",
                        "priority": "high",
                    }
                ],
            },
            "status": "error",
        }

    current_level: int = state.get("current_level", 0)
    level_results: dict = state.get("level_results", {})
    final_score: float = state.get("final_score", 0.0)
    platform_data: PlatformData | None = state.get("platform_data")

    # The highest completed level's result drives the output
    level_data = level_results.get(current_level, {})

    score_min, score_max = LEVEL_SCORE_RANGES.get(current_level, (0.0, 0.0))
    score_range = f"{score_min}–{score_max}"

    # Aggregate recommendations from all levels
    all_recommendations = []
    for lvl in sorted(level_results.keys()):
        for rec in level_results[lvl].get("recommendations", []):
            all_recommendations.append(rec)

    final_result = {
        "maturity_level": current_level,
        "score": round(final_score, 2),
        "score_range": score_range,
        "assessment_details": {
            "passed_criteria": level_data.get("passed_criteria", []),
            "failed_criteria": level_data.get("failed_criteria", []),
            "reasoning": level_data.get("reasoning", ""),
        },
        "improvement_recommendations": all_recommendations,
        "platform": {
            "type": platform_data.platform_type if platform_data else "unknown",
            "repository": platform_data.repository if platform_data else "unknown",
            "api_call_log": platform_data.api_call_log if platform_data else [],
        },
        "level_breakdown": {
            str(lvl): {
                "passed": level_results[lvl].get("passed"),
                "score": level_results[lvl].get("score"),
            }
            for lvl in sorted(level_results.keys())
        },
    }

    logger.info(
        "format_result_node: final maturity_level=%d score=%.2f",
        current_level,
        final_score,
    )

    return {"final_result": final_result, "status": "completed"}
