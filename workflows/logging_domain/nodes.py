"""
Node functions for the logging_domain workflow.

Node 0 (collect_platform_data_node) queries BOTH a VCS connector and a Cloud
connector (dual registry pattern) and merges their signals into platform_data.
Nodes 1-5 assess each maturity level against that merged platform_data.
format_result_node is always terminal.
"""

import json
import re

from langchain_core.messages import HumanMessage, SystemMessage

from core.logger import get_logger
from core.llm_provider import LLMProvider
from workflows.logging_domain.config import (
    LEVEL_DESCRIPTIONS,
    LEVEL_CRITERIA_NAMES,
    LEVEL_PROMPTS,
)
from workflows.logging_domain.connectors import (
    VCS_CONNECTOR_REGISTRY,
    CLOUD_CONNECTOR_REGISTRY,
)

logger = get_logger(__name__)

ALL_LEVELS = [1, 2, 3, 4, 5]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _call_llm_json(system_prompt: str, user_content: str) -> dict:
    llm = LLMProvider().get_llm()
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


def _build_platform_summary(state: dict) -> str:
    """Build the LLM-facing summary from merged VCS + Cloud platform data.

    IMPORTANT: raw configuration content is passed through (truncated, not
    stripped to booleans) so the LLM can reason over actual log-shipping /
    security-event / PII-policy signals rather than pre-computed flags alone.
    """
    vcs_data = state.get("vcs_data")
    cloud_data = state.get("cloud_data")
    lines: list[str] = []

    if vcs_data:
        lines.append(f"=== VCS Platform: {vcs_data.platform_type} | Repo: {vcs_data.repository} ===")
        lines.append(f"Logging config files found: {vcs_data.logging_config_files_found}")
        lines.append(f"Correlation IDs detected in config: {vcs_data.correlation_ids_detected}")
        lines.append(f"PII logging policy doc found: {vcs_data.pii_logging_policy_doc_found}")
        for src in vcs_data.log_sources:
            lines.append(f"--- Source: {src.path} ---")
            lines.append(
                f"ships_to_centralized_system={src.ships_to_centralized_system} "
                f"logs_security_events={src.logs_security_events} "
                f"logs_login_logout={src.logs_login_logout} "
                f"logs_user_lifecycle_events={src.logs_user_lifecycle_events}"
            )
            if src.raw_content:
                lines.append(f"raw_content (truncated):\n{src.raw_content[:3000]}")

    if cloud_data:
        cls = cloud_data.centralized_log_system
        sec = cloud_data.security_events
        analysis = cloud_data.log_analysis
        lines.append(f"=== Cloud Platform: {cloud_data.platform_type} ===")
        lines.append(
            f"Centralized log system: name={cls.system_name!r} "
            f"sources_ingesting={cls.sources_ingesting} "
            f"storage_encrypted={cls.storage_encrypted} "
            f"retention_days={cls.retention_days} "
            f"integrity_protection_enabled={cls.integrity_protection_enabled} "
            f"alerting_configured={cls.alerting_configured}"
        )
        lines.append(
            f"Security events: login_logout_logged={sec.login_logout_logged} "
            f"user_created_logged={sec.user_created_logged} "
            f"user_changed_logged={sec.user_changed_logged} "
            f"user_deleted_logged={sec.user_deleted_logged} "
            f"correlation_across_sources={sec.correlation_across_sources}"
        )
        lines.append(
            f"Log analysis/visualization: keyword_search_supported={analysis.keyword_search_supported} "
            f"attack_detection_rules_configured={analysis.attack_detection_rules_configured} "
            f"real_time_dashboard_available={analysis.real_time_dashboard_available} "
            f"gui_search_available={analysis.gui_search_available} "
            f"developer_access_to_app_logs={analysis.developer_access_to_app_logs}"
        )
        lines.append(f"Correlated event visualizations: {cloud_data.correlated_event_visualizations}")

    return "\n".join(lines) if lines else "No platform data collected."


def _parse_criterion(item) -> tuple[str, str]:
    """Parse a {name, reason} object or fall back to a plain string."""
    if isinstance(item, dict):
        return item.get("name", ""), item.get("reason", "")
    return item, ""


def _merged_api_call_log(state: dict) -> list[str]:
    log: list[str] = []
    vcs_data = state.get("vcs_data")
    cloud_data = state.get("cloud_data")
    if vcs_data:
        log.extend(vcs_data.api_call_log)
    if cloud_data:
        log.extend(cloud_data.api_call_log)
    return log


# ---------------------------------------------------------------------------
# Node 0: collect platform data (dual: VCS + Cloud)
# ---------------------------------------------------------------------------

async def collect_platform_data_node(state: dict) -> dict:
    logger.info("── collect_platform_data_node: START ──")

    from core.database import SessionLocal
    from core.repositories.assessment_result_repository import AssessmentResultRepository

    assessment_id = state.get("assessment_id")
    result_id = None
    db = SessionLocal()
    try:
        result_id = AssessmentResultRepository.insert_assessment_result_returning_id(
            db=db,
            assessment_id=assessment_id,
            status="IN_PROGRESS",
            domain_name="Logging",
        )
    except Exception as exc:
        logger.error("Failed to insert initial IN_PROGRESS assessment result: %s", exc, exc_info=True)
    finally:
        db.close()

    vcs_platform_type = state.get("vcs_platform_type")
    cloud_platform_type = state.get("cloud_platform_type")
    vcs_credentials = state.get("vcs_credentials", {})
    cloud_credentials = state.get("cloud_credentials", {})
    repository = state.get("repository")
    branch = state.get("branch", "").strip()

    vcs_connector_cls = VCS_CONNECTOR_REGISTRY.get(vcs_platform_type)
    cloud_connector_cls = CLOUD_CONNECTOR_REGISTRY.get(cloud_platform_type)

    if not vcs_connector_cls:
        logger.error("Unsupported vcs_platform_type: %s", vcs_platform_type)
        return {
            "status": "error",
            "error_message": f"Unsupported vcs_platform_type: {vcs_platform_type}",
            "stop_assessment": True,
            "result_id": result_id,
        }
    if not cloud_connector_cls:
        logger.error("Unsupported cloud_platform_type: %s", cloud_platform_type)
        return {
            "status": "error",
            "error_message": f"Unsupported cloud_platform_type: {cloud_platform_type}",
            "stop_assessment": True,
            "result_id": result_id,
        }

    vcs_connector = vcs_connector_cls(vcs_credentials)
    cloud_connector = cloud_connector_cls(cloud_credentials)

    vcs_healthy = await vcs_connector.health_check()
    if not vcs_healthy:
        logger.error("VCS connector health_check failed for %s", vcs_platform_type)
        return {
            "status": "error",
            "error_message": f"VCS platform '{vcs_platform_type}' health check failed. Check credentials.",
            "stop_assessment": True,
            "result_id": result_id,
        }

    cloud_healthy = await cloud_connector.health_check()
    if not cloud_healthy:
        logger.error("Cloud connector health_check failed for %s", cloud_platform_type)
        return {
            "status": "error",
            "error_message": f"Cloud platform '{cloud_platform_type}' health check failed. Check credentials.",
            "stop_assessment": True,
            "result_id": result_id,
        }

    try:
        vcs_data = await vcs_connector.collect(repository, branch=branch)
    except Exception as exc:
        logger.error("VCS collect() failed: %s", exc, exc_info=True)
        return {
            "status": "error",
            "error_message": f"Failed to collect data from VCS platform: {exc}",
            "stop_assessment": True,
            "result_id": result_id,
        }

    try:
        cloud_data = await cloud_connector.collect()
    except Exception as exc:
        logger.error("Cloud collect() failed: %s", exc, exc_info=True)
        return {
            "status": "error",
            "error_message": f"Failed to collect data from cloud platform: {exc}",
            "stop_assessment": True,
            "result_id": result_id,
        }

    logger.info("── collect_platform_data_node: result=collected ──")
    return {
        "vcs_data": vcs_data,
        "cloud_data": cloud_data,
        "status": "data_collected",
        "stop_assessment": False,
        "result_id": result_id,
    }


# ---------------------------------------------------------------------------
# Level nodes
# ---------------------------------------------------------------------------

async def _level_node(state: dict, level: int) -> dict:
    if state.get("stop_assessment"):
        return {}

    logger.info("── level%d_node: START ──", level)
    try:
        summary = _build_platform_summary(state)
        logger.info("level%d_node: Data provided to LLM:\n%s", level, summary)
        result = await _call_llm_json(LEVEL_PROMPTS[level], summary)

        if "error" in result:
            logger.error("level%d_node: LLM error=%s", level, result["error"])
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

        logger.info("── level%d_node: result=passed=%s score=%s ──", level, passed, score)

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
    except Exception as exc:
        logger.error("level%d_node failed: %s", level, exc, exc_info=True)
        return {
            "status": "error",
            "error_message": str(exc),
            "stop_assessment": True,
            "current_level": level,
        }


async def level1_node(state: dict) -> dict:
    return await _level_node(state, 1)


async def level2_node(state: dict) -> dict:
    return await _level_node(state, 2)


async def level3_node(state: dict) -> dict:
    return await _level_node(state, 3)


async def level4_node(state: dict) -> dict:
    # Level 4 placeholder — auto-pass (Rule 25), still routed through the
    # standard LLM call so level_results/format_result_node logic stays uniform.
    return await _level_node(state, 4)


async def level5_node(state: dict) -> dict:
    return await _level_node(state, 5)


# ---------------------------------------------------------------------------
# Terminal node: format_result
# ---------------------------------------------------------------------------

async def format_result_node(state: dict) -> dict:
    logger.info("── format_result_node: START ──")

    from workflows.logging_domain.config import LEVEL_SCORE_RANGES

    level_results = state.get("level_results", {})
    current_level = state.get("current_level")
    error_message = state.get("error_message")
    result_id = state.get("result_id")

    # Determine highest level reached and the maturity level/score
    if error_message and not level_results:
        final_result = {
            "domain": "Logging",
            "maturity_level": 0,
            "score": 0.0,
            "score_range": None,
            "assessment_details": {
                "passed_criteria": [],
                "failed_criteria": [],
                "overall_reasoning": f"Assessment could not complete: {error_message}",
            },
            "improvement_recommendations": [],
            "level_wise_criteria": [],
            "level_breakdown": {},
            "platform": {"api_call_log": _merged_api_call_log(state)},
        }
        _persist(result_id, final_result, status="FAILED", reasoning=error_message)
        return {"final_result": final_result, "status": "failed"}

    # Highest passed level determines maturity_level; if the halting level
    # failed, maturity_level = last fully passed level (current_level - 1),
    # unless current_level itself passed (i.e., assessment ran to completion).
    last_result = level_results.get(current_level, {}) if current_level else {}
    if last_result.get("passed"):
        maturity_level = current_level
        score = last_result.get("score", LEVEL_SCORE_RANGES.get(current_level, (0, 0))[1])
    else:
        maturity_level = (current_level - 1) if current_level else 0
        score = last_result.get("score", LEVEL_SCORE_RANGES.get(current_level, (0, 0))[0]) \
            if current_level else 0.0

    score_min, score_max = LEVEL_SCORE_RANGES.get(maturity_level, (0.0, 0.0))
    score_range = f"{score_min}-{score_max}"

    # Aggregate passed/failed criteria (flat, tagged with level) across all
    # completed levels, plus aggregate recommendations.
    passed_criteria: list[dict] = []
    failed_criteria: list[dict] = []
    improvement_recommendations: list[dict] = []

    for lvl in ALL_LEVELS:
        res = level_results.get(lvl)
        if not res:
            continue
        for item in res.get("passed_criteria", []):
            name, reason = _parse_criterion(item)
            passed_criteria.append({"level": lvl, "criteria": name, "status": "PASSED"})
        for item in res.get("failed_criteria", []):
            name, reason = _parse_criterion(item)
            failed_criteria.append({"level": lvl, "criteria": name, "status": "FAILED", "reason": reason})
        for rec in res.get("recommendations", []):
            improvement_recommendations.append({
                "gap": rec.get("gap", ""),
                "current_limitation": rec.get("current_limitation", ""),
                "recommended_action": rec.get("action", ""),
                "related_level": lvl,
                "priority": rec.get("priority", "medium"),
            })

    # Build overall_reasoning
    if current_level and not last_result.get("passed"):
        halting_name = LEVEL_DESCRIPTIONS.get(current_level, f"Level {current_level}")
        overall_reasoning = (
            f"Assessment reached Level {current_level} ({halting_name}) and stopped there: "
            f"{last_result.get('reasoning', 'one or more criteria were not met')}. "
            f"Confirmed maturity level is {maturity_level}."
        )
    elif current_level:
        overall_reasoning = (
            f"Assessment completed through Level {current_level} "
            f"({LEVEL_DESCRIPTIONS.get(current_level, '')}): "
            f"{last_result.get('reasoning', 'all criteria met')}."
        )
    else:
        overall_reasoning = "Assessment did not evaluate any levels."

    # Build level_wise_criteria for ALL 5 levels
    failed_at_level = None
    for lvl in ALL_LEVELS:
        if lvl in level_results and not level_results[lvl].get("passed", True):
            failed_at_level = lvl
            break

    level_wise_criteria = []
    level_breakdown: dict[str, dict] = {}
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
            level_breakdown[str(lvl)] = {"passed": res.get("passed", False), "score": res.get("score")}
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
                "criteria": [
                    {"name": c, "status": "NOT_CHECKED", "reason": skip_reason} for c in canonical
                ],
            })

    final_result = {
        "domain": "Logging",
        "maturity_level": maturity_level,
        "score": score,
        "score_range": score_range,
        "assessment_details": {
            "passed_criteria": passed_criteria,
            "failed_criteria": failed_criteria,
            "overall_reasoning": overall_reasoning,
        },
        "improvement_recommendations": improvement_recommendations,
        "level_wise_criteria": level_wise_criteria,
        "level_breakdown": level_breakdown,
        "platform": {"api_call_log": _merged_api_call_log(state)},
    }

    _persist(result_id, final_result, status="COMPLETED", reasoning=overall_reasoning)

    logger.info("── format_result_node: result=maturity_level=%s score=%s ──", maturity_level, score)
    return {"final_result": final_result, "status": "completed"}


def _persist(result_id, final_result: dict, status: str, reasoning: str) -> None:
    if not result_id:
        return
    try:
        from core.database import SessionLocal
        from core.repositories.assessment_result_repository import AssessmentResultRepository

        db = SessionLocal()
        try:
            AssessmentResultRepository.update_assessment_result(
                db=db,
                result_id=result_id,
                status=status,
                domain_score=final_result.get("score", 0.0),
                reasoning=reasoning,
                improvement_recommendations=final_result.get("improvement_recommendations", []),
                additional_info=final_result,
            )
        finally:
            db.close()
    except Exception as db_exc:
        logger.error("Failed to persist final assessment result: %s", db_exc, exc_info=True)
