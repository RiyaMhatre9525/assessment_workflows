"""
Node functions for the Monitoring Maturity Assessment workflow.

Mirrors workflows/build_domain/nodes.py structure exactly:
  - collect_platform_data_node (dual VCS + Cloud collection)
  - level1_node .. level5_node
  - format_result_node (terminal, always runs)
  - _should_stop (fail-fast routing helper, used by graph.py)
  - _parse_criterion / _call_llm_json (shared helpers)
"""

import json
import re

from langchain_core.messages import HumanMessage, SystemMessage

from core.logger import get_logger
from core.llm_provider import LLMProvider
from core.database import SessionLocal
from core.repositories.assessment_result_repository import AssessmentResultRepository

from .config import (
    LEVEL_DESCRIPTIONS,
    LEVEL_CRITERIA_NAMES,
    LEVEL1_SYSTEM_PROMPT,
    LEVEL2_SYSTEM_PROMPT,
    LEVEL3_SYSTEM_PROMPT,
    LEVEL4_SYSTEM_PROMPT,
    LEVEL5_SYSTEM_PROMPT,
)
from .connectors import VCS_CONNECTOR_REGISTRY, CLOUD_CONNECTOR_REGISTRY

logger = get_logger(__name__)

DOMAIN_NAME = "Monitoring"
ALL_LEVELS = [1, 2, 3, 4, 5]

LEVEL_PROMPTS = {
    1: LEVEL1_SYSTEM_PROMPT,
    2: LEVEL2_SYSTEM_PROMPT,
    3: LEVEL3_SYSTEM_PROMPT,
    4: LEVEL4_SYSTEM_PROMPT,
    5: LEVEL5_SYSTEM_PROMPT,
}


# ─────────────────────────────────────────────────────────────────────────
# Shared helpers
# ─────────────────────────────────────────────────────────────────────────
async def _call_llm_json(system_prompt: str, user_content: str) -> dict:
    llm = LLMProvider().get_llm()
    logger.info("Calling LLM with system prompt:\n%s", system_prompt)
    logger.info("Calling LLM with user content:\n%s", user_content)
    try:
        response = await llm.ainvoke([
            SystemMessage(content=system_prompt),
            HumanMessage(content=user_content),
        ])
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


def _parse_criterion(item) -> tuple[str, str]:
    if isinstance(item, dict):
        return item.get("name", ""), item.get("reason", "")
    return item, ""


def _build_platform_summary(state: dict) -> str:
    """Builds the raw-content summary passed to the LLM. Raw config/metadata
    content is passed through as-is (never pre-flattened into booleans) —
    this mirrors the fix traced back to the build_domain underscoring bug."""
    vcs_data = state.get("vcs_data")
    cloud_data = state.get("cloud_data")

    parts = []

    if vcs_data is not None:
        parts.append(f"### VCS Platform: {vcs_data.platform_type} (repo: {vcs_data.repository})")
        if vcs_data.monitoring_config_files:
            parts.append("Monitoring-as-code configuration files found:")
            for f in vcs_data.monitoring_config_files:
                parts.append(f"--- {f.path} ---\n{f.raw_content}")
        else:
            parts.append("No monitoring-as-code configuration files found.")
        if vcs_data.ci_monitoring_steps:
            parts.append("CI/pipeline files referencing monitoring:")
            for f in vcs_data.ci_monitoring_steps:
                parts.append(f"--- {f.path} ---\n{f.raw_content}")
        else:
            parts.append("No CI/pipeline monitoring steps found.")

    if cloud_data is not None:
        parts.append(f"\n### Cloud Platform: {cloud_data.platform_type} (subscription: {cloud_data.subscription_id})")
        parts.append(f"Metric alert rules (raw): {json.dumps(cloud_data.metric_alert_rules)[:4000]}")
        parts.append(f"Action groups (raw): {json.dumps(cloud_data.action_groups)[:2000]}")
        parts.append(f"Cost budgets (raw): {json.dumps(cloud_data.cost_budgets)[:3000]}")
        parts.append(f"Diagnostic settings (raw): {json.dumps(cloud_data.diagnostic_settings)[:3000]}")
        parts.append(f"Dashboards (raw): {json.dumps(cloud_data.dashboards)[:2000]}")
        parts.append(f"Security metric sources (raw): {json.dumps(cloud_data.security_metric_sources)[:3000]}")

    return "\n\n".join(parts)


def _should_stop(state: dict) -> str:
    return "format_result" if state.get("stop_assessment") else "continue"


# ─────────────────────────────────────────────────────────────────────────
# Node 0: collect platform data (VCS + Cloud)
# ─────────────────────────────────────────────────────────────────────────
async def collect_platform_data_node(state: dict) -> dict:
    logger.info("── collect_platform_data: START ──")

    result_id = None
    try:
        db = SessionLocal()
        try:
            result_id = AssessmentResultRepository.insert_assessment_result_returning_id(
                db=db,
                assessment_id=state.get("assessment_id"),
                status="IN_PROGRESS",
                domain_name=DOMAIN_NAME,
            )
        finally:
            db.close()
    except Exception as exc:
        logger.error("Failed to insert initial assessment result: %s", exc)

    vcs_platform_type = state.get("vcs_platform_type")
    cloud_platform_type = state.get("cloud_platform_type")
    repository = state.get("repository")

    vcs_connector_cls = VCS_CONNECTOR_REGISTRY.get(vcs_platform_type)
    cloud_connector_cls = CLOUD_CONNECTOR_REGISTRY.get(cloud_platform_type)

    if not vcs_connector_cls:
        return {
            "status": "error",
            "error_message": f"Unsupported vcs_platform_type: {vcs_platform_type}",
            "stop_assessment": True,
            "result_id": result_id,
        }
    if not cloud_connector_cls:
        return {
            "status": "error",
            "error_message": f"Unsupported cloud_platform_type: {cloud_platform_type}",
            "stop_assessment": True,
            "result_id": result_id,
        }

    vcs_connector = vcs_connector_cls(state.get("vcs_credentials", {}))
    cloud_connector = cloud_connector_cls(state.get("cloud_credentials", {}))

    try:
        vcs_ok = await vcs_connector.health_check()
        if not vcs_ok:
            return {
                "status": "error",
                "error_message": f"VCS health check failed for platform '{vcs_platform_type}'.",
                "stop_assessment": True,
                "result_id": result_id,
            }

        cloud_ok = await cloud_connector.health_check()
        if not cloud_ok:
            return {
                "status": "error",
                "error_message": f"Cloud health check failed for platform '{cloud_platform_type}'.",
                "stop_assessment": True,
                "result_id": result_id,
            }

        vcs_data = await vcs_connector.collect(repository)
        cloud_data = await cloud_connector.collect(repository)

    except Exception as exc:
        logger.error("collect_platform_data failed: %s", exc, exc_info=True)
        return {
            "status": "error",
            "error_message": str(exc),
            "stop_assessment": True,
            "result_id": result_id,
        }

    logger.info("── collect_platform_data: result=collected VCS+Cloud data ──")
    return {
        "vcs_data": vcs_data,
        "cloud_data": cloud_data,
        "status": "data_collected",
        "stop_assessment": False,
        "result_id": result_id,
    }


# ─────────────────────────────────────────────────────────────────────────
# Level nodes 1-5
# ─────────────────────────────────────────────────────────────────────────
async def _run_level_node(state: dict, level: int) -> dict:
    if state.get("stop_assessment"):
        return {}

    logger.info("── level%s: START ──", level)
    summary = _build_platform_summary(state)
    result = await _call_llm_json(LEVEL_PROMPTS[level], summary)

    if "error" in result:
        logger.error("── level%s: LLM error=%s ──", level, result["error"])
        return {
            "status": "error",
            "error_message": result["error"],
            "stop_assessment": True,
            "current_level": level,
        }

    level_results = dict(state.get("level_results", {}))
    level_results[level] = result

    passed = bool(result.get("passed"))
    score = result.get("score")

    logger.info("── level%s: result=passed=%s score=%s ──", level, passed, score)

    if passed:
        return {
            "level_results": level_results,
            "current_level": level,
            "stop_assessment": False,
        }

    return {
        "level_results": level_results,
        "current_level": level,
        "final_score": score,
        "stop_assessment": True,
        "status": f"assessment_stopped_at_level_{level}",
    }


async def level1_node(state: dict) -> dict:
    return await _run_level_node(state, 1)


async def level2_node(state: dict) -> dict:
    return await _run_level_node(state, 2)


async def level3_node(state: dict) -> dict:
    return await _run_level_node(state, 3)


async def level4_node(state: dict) -> dict:
    return await _run_level_node(state, 4)


async def level5_node(state: dict) -> dict:
    return await _run_level_node(state, 5)


# ─────────────────────────────────────────────────────────────────────────
# Terminal node: always runs
# ─────────────────────────────────────────────────────────────────────────
async def format_result_node(state: dict) -> dict:
    logger.info("── format_result: START ──")

    level_results: dict = state.get("level_results", {})
    result_id = state.get("result_id")
    error_message = state.get("error_message")
    current_level = state.get("current_level", 0)

    # Determine highest passed level and final score
    passed_levels = [lvl for lvl in ALL_LEVELS if lvl in level_results and level_results[lvl].get("passed")]
    maturity_level = max(passed_levels) if passed_levels else 0

    if state.get("final_score") is not None:
        final_score = state["final_score"]
    elif maturity_level in level_results:
        final_score = level_results[maturity_level].get("score", float(maturity_level))
    else:
        final_score = 0.0

    score_range = f"{max(maturity_level - 1, 0)}.0-{maturity_level}.0" if maturity_level else "0.0-1.0"

    # The highest evaluated level's result drives the output details
    level_data = level_results.get(current_level, {})

    # Aggregate recommendations across all completed (evaluated) levels
    improvement_recommendations = []
    for lvl in ALL_LEVELS:
        if lvl in level_results:
            improvement_recommendations.extend(level_results[lvl].get("recommendations", []))

    # Find first failing level for skip reason
    failed_at_level = None
    for lvl in ALL_LEVELS:
        if lvl in level_results and not level_results[lvl].get("passed", True):
            failed_at_level = lvl
            break

    # Build level_wise_criteria for ALL 5 levels (Rule 30)
    level_wise_criteria = []

    for lvl in ALL_LEVELS:
        lvl_name = LEVEL_DESCRIPTIONS.get(lvl, f"Level {lvl}")

        if lvl in level_results:
            res = level_results[lvl]
            criteria_list = []
            for item in res.get("passed_criteria", []):
                name, reason = _parse_criterion(item)
                criteria_list.append({"name": name, "status": "PASSED", "reason": reason})
            for item in res.get("failed_criteria", []):
                name, reason = _parse_criterion(item)
                criteria_list.append({"name": name, "status": "FAILED", "reason": reason})

            level_wise_criteria.append({
                "level": lvl,
                "level_name": lvl_name,
                "status": "PASSED" if res.get("passed") else "FAILED",
                "checked": True,
                "score": res.get("score"),
                "reasoning": res.get("reasoning", ""),
                "criteria": criteria_list,
            })
        else:
            if failed_at_level:
                failed_name = LEVEL_DESCRIPTIONS.get(failed_at_level, f"Level {failed_at_level}")
                skip_reason = (
                    f"Level {failed_at_level} ({failed_name}) did not pass — "
                    f"assessment halted before reaching this level."
                )
            else:
                skip_reason = "Assessment did not reach this level."
            canonical = LEVEL_CRITERIA_NAMES.get(lvl, [])
            level_wise_criteria.append({
                "level": lvl,
                "level_name": lvl_name,
                "status": "NOT_CHECKED",
                "checked": False,
                "score": None,
                "reasoning": None,
                "criteria": [{"name": c, "status": "NOT_CHECKED", "reason": skip_reason} for c in canonical],
            })

    # Compact level_breakdown (Rule 27)
    level_breakdown = {
        str(lvl): {"passed": level_results[lvl].get("passed"), "score": level_results[lvl].get("score")}
        for lvl in ALL_LEVELS
        if lvl in level_results
    }

    vcs_data = state.get("vcs_data")
    cloud_data = state.get("cloud_data")
    platform_api_call_log = {
        "vcs": list(vcs_data.api_call_log) if vcs_data is not None else [],
        "cloud": list(cloud_data.api_call_log) if cloud_data is not None else [],
    }

    final_result = {
        "workflow_domain": DOMAIN_NAME,
        "maturity_level": maturity_level,
        "score": final_score,
        "score_range": score_range,
        "assessment_details": {
            "passed_criteria": level_data.get("passed_criteria", []),
            "failed_criteria": level_data.get("failed_criteria", []),
            "reasoning": level_data.get("reasoning", "") or error_message or "",
        },
        "improvement_recommendations": improvement_recommendations,
        "level_wise_criteria": level_wise_criteria,
        "level_breakdown": level_breakdown,
        "platform_api_call_log": platform_api_call_log,
    }

    status = "FAILED" if error_message else "COMPLETED"

    if result_id:
        db = SessionLocal()
        try:
            AssessmentResultRepository.update_assessment_result(
                db=db,
                result_id=result_id,
                status=status,
                domain_score=final_score,
                reasoning=level_data.get("reasoning", "") or error_message or "Assessment completed.",
                improvement_recommendations=improvement_recommendations,
                additional_info=final_result,
            )
        except Exception as exc:
            logger.error("Failed to update assessment result: %s", exc, exc_info=True)
        finally:
            db.close()

    logger.info("── format_result: result=maturity_level=%s score=%s ──", maturity_level, final_score)
    return {"final_result": final_result, "status": "completed"}
