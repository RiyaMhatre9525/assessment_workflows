"""
Node functions for the patch_management workflow.

One node per maturity level plus a data-collection node and a terminal
format_result node, following the same conventions as workflows/build_domain.
"""

import json
import re

from core.logger import get_logger
from core.llm_provider import LLMProvider
from langchain_core.messages import HumanMessage, SystemMessage

from workflows.patch_management.config import (
    LEVEL1_SYSTEM_PROMPT,
    LEVEL2_SYSTEM_PROMPT,
    LEVEL3_SYSTEM_PROMPT,
    LEVEL4_SYSTEM_PROMPT,
    LEVEL_CRITERIA_NAMES,
    LEVEL_DESCRIPTIONS,
)
from workflows.patch_management.connectors import CONNECTOR_REGISTRY

logger = get_logger(__name__)


# --------------------------------------------------------------------------- #
# Shared helpers
# --------------------------------------------------------------------------- #

async def _async_llm(system_prompt: str, user_content: str) -> dict:
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


def _parse_criterion(item) -> tuple[str, str]:
    """Parse a {name, reason} object or fall back to a plain string."""
    if isinstance(item, dict):
        return item.get("name", ""), item.get("reason", "")
    return item, ""


# --------------------------------------------------------------------------- #
# Node 0: collect platform data
# --------------------------------------------------------------------------- #

async def collect_platform_data_node(state: dict) -> dict:
    logger.info("── collect_platform_data: START ──")

    result_id = None
    try:
        from core.database import SessionLocal
        from core.repositories.assessment_result_repository import AssessmentResultRepository

        db = SessionLocal()
        try:
            result_id = AssessmentResultRepository.insert_assessment_result_returning_id(
                db=db,
                assessment_id=state.get("assessment_id"),
                status="IN_PROGRESS",
                domain_name="patch_management",
            )
        finally:
            db.close()
    except Exception as db_exc:
        logger.error("Failed to insert IN_PROGRESS assessment record: %s", db_exc)

    platform_type = state.get("platform_type")
    connector_cls = CONNECTOR_REGISTRY.get(platform_type)
    if connector_cls is None:
        logger.error("Unsupported platform_type: %s", platform_type)
        return {
            "status": "error",
            "error_message": f"Unsupported platform '{platform_type}'.",
            "stop_assessment": True,
            "result_id": result_id,
        }

    try:
        connector = connector_cls(state.get("credentials", {}))
        healthy = await connector.health_check()
        if not healthy:
            logger.error("Health check failed for platform: %s", platform_type)
            return {
                "status": "error",
                "error_message": "Authentication failed or platform unreachable.",
                "stop_assessment": True,
                "result_id": result_id,
            }

        platform_data = await connector.collect(state.get("repository", ""))
        logger.info("── collect_platform_data: result=collected ──")
        return {
            "platform_data": platform_data,
            "status": "data_collected",
            "stop_assessment": False,
            "result_id": result_id,
        }
    except Exception as exc:
        logger.error("collect_platform_data_node failed: %s", exc, exc_info=True)
        return {
            "status": "error",
            "error_message": str(exc),
            "stop_assessment": True,
            "result_id": result_id,
        }


# --------------------------------------------------------------------------- #
# Level 1: Patch Policy & Automated Pull Requests
# --------------------------------------------------------------------------- #

async def level1_node(state: dict) -> dict:
    if state.get("stop_assessment"):
        return {}
    logger.info("── level1: START ──")
    try:
        pd = state["platform_data"]
        summary = (
            f"Patch Policy evidence:\n"
            f"  - policy_document_found: {pd.policy.policy_document_found}\n"
            f"  - source: {pd.policy.source}\n"
            f"  - mentions_frequency: {pd.policy.mentions_frequency}\n"
            f"  - mentions_responsibilities: {pd.policy.mentions_responsibilities}\n"
            f"  - mentions_review_process: {pd.policy.mentions_review_process}\n\n"
            f"Automated Pull Requests evidence:\n"
            f"  - tool_detected: {pd.dependency_automation.tool_detected}\n"
            f"  - config_found: {pd.dependency_automation.config_found}\n"
            f"  - automated_prs_open_count: {pd.dependency_automation.automated_prs_open_count}\n"
            f"  - automated_prs_merged_count: {pd.dependency_automation.automated_prs_merged_count}\n"
            f"  - vulnerability_alerts_enabled: {pd.dependency_automation.vulnerability_alerts_enabled}\n"
            f"  - sample_pr_titles: {pd.dependency_automation.sample_pr_titles}\n"
        )
        result = await _async_llm(LEVEL1_SYSTEM_PROMPT, summary)
        logger.info("── level1: LLM result=%s", result) 
        if "error" in result:
            return {"status": "error", "error_message": result["error"], "stop_assessment": True}
        
        

        level_results = dict(state.get("level_results", {}))
        level_results[1] = result

        if result.get("passed"):
            return {"level_results": level_results, "current_level": 1, "stop_assessment": False}
        return {
            "level_results": level_results,
            "current_level": 1,
            "final_score": result.get("score", 0.0),
            "stop_assessment": True,
            "status": "assessment_stopped_at_level_1",
        }
    except Exception as exc:
        logger.error("level1_node failed: %s", exc, exc_info=True)
        return {"status": "error", "error_message": str(exc), "stop_assessment": True}


# --------------------------------------------------------------------------- #
# Level 2: Automated Merge, Nightly Builds & Image Hygiene
# --------------------------------------------------------------------------- #

async def level2_node(state: dict) -> dict:
    if state.get("stop_assessment"):
        return {}
    logger.info("── level2: START ──")
    try:
        pd = state["platform_data"]
        summary = (
            f"Automated Merge evidence:\n"
            f"  - auto_merge_enabled: {pd.merge_automation.auto_merge_enabled}\n"
            f"  - mechanism: {pd.merge_automation.mechanism}\n"
            f"  - validation_required: {pd.merge_automation.validation_required}\n\n"
            f"Nightly Base Image Builds evidence:\n"
            f"  - scheduled_pipeline_found: {pd.nightly_build.scheduled_pipeline_found}\n"
            f"  - schedule_expression: {pd.nightly_build.schedule_expression}\n"
            f"  - pipeline_name: {pd.nightly_build.pipeline_name}\n\n"
            f"Reduction of Attack Surface evidence:\n"
            f"  - dockerfiles_inspected: {pd.attack_surface.dockerfiles_inspected}\n"
            f"  - minimal_base_image_count: {pd.attack_surface.minimal_base_image_count}\n"
            f"  - base_images_found: {pd.attack_surface.base_images_found}\n"
            f"  - inspection_possible: {pd.attack_surface.inspection_possible}\n"
            f"  - limitation_note: {pd.attack_surface.limitation_note}\n\n"
            f"Maximum Lifetime of Images evidence:\n"
            f"  - registry_accessible: {pd.image_lifecycle.registry_accessible}\n"
            f"  - images_checked: {pd.image_lifecycle.images_checked}\n"
            f"  - max_image_age_days: {pd.image_lifecycle.max_image_age_days}\n"
            f"  - rebuild_frequency_days: {pd.image_lifecycle.rebuild_frequency_days}\n"
            f"  - limitation_note: {pd.image_lifecycle.limitation_note}\n"
        )
        logger.info("── level2: summary=%s", summary)
        result = await _async_llm(LEVEL2_SYSTEM_PROMPT, summary)
        logger.info("── level2: LLM result=%s", result) 
        if "error" in result:
            return {"status": "error", "error_message": result["error"], "stop_assessment": True}

        level_results = dict(state.get("level_results", {}))
        level_results[2] = result

        if result.get("passed"):
            return {"level_results": level_results, "current_level": 2, "stop_assessment": False}
        return {
            "level_results": level_results,
            "current_level": 2,
            "final_score": result.get("score", 0.0),
            "stop_assessment": True,
            "status": "assessment_stopped_at_level_2",
        }
    except Exception as exc:
        logger.error("level2_node failed: %s", exc, exc_info=True)
        return {"status": "error", "error_message": str(exc), "stop_assessment": True}


# --------------------------------------------------------------------------- #
# Level 3: Automated Deployment
# --------------------------------------------------------------------------- #

async def level3_node(state: dict) -> dict:
    if state.get("stop_assessment"):
        return {}
    logger.info("── level3: START ──")
    try:
        pd = state["platform_data"]
        summary = (
            f"Automated Deployment evidence:\n"
            f"  - deployment_pipeline_found: {pd.deployment.deployment_pipeline_found}\n"
            f"  - pipeline_name: {pd.deployment.pipeline_name}\n"
            f"  - auto_triggered: {pd.deployment.auto_triggered}\n"
            f"  - trigger_type: {pd.deployment.trigger_type}\n"
            f"  - deploys_dependency_updates: {pd.deployment.deploys_dependency_updates}\n"
        )
        logger.info("── level3: summary=%s", summary)
        result = await _async_llm(LEVEL3_SYSTEM_PROMPT, summary)
        if "error" in result:
            return {"status": "error", "error_message": result["error"], "stop_assessment": True}

        level_results = dict(state.get("level_results", {}))
        level_results[3] = result

        if result.get("passed"):
            return {"level_results": level_results, "current_level": 3, "stop_assessment": False}
        return {
            "level_results": level_results,
            "current_level": 3,
            "final_score": result.get("score", 0.0),
            "stop_assessment": True,
            "status": "assessment_stopped_at_level_3",
        }
    except Exception as exc:
        logger.error("level3_node failed: %s", exc, exc_info=True)
        return {"status": "error", "error_message": str(exc), "stop_assessment": True}


# --------------------------------------------------------------------------- #
# Level 4: Short Maximum Lifetime for Images
# --------------------------------------------------------------------------- #

async def level4_node(state: dict) -> dict:
    if state.get("stop_assessment"):
        return {}
    logger.info("── level4: START ──")
    try:
        pd = state["platform_data"]
        summary = (
            f"Short Maximum Lifetime for Images evidence:\n"
            f"  - registry_accessible: {pd.image_lifecycle.registry_accessible}\n"
            f"  - rebuild_frequency_days: {pd.image_lifecycle.rebuild_frequency_days}\n"
            f"  - avg_image_age_days: {pd.image_lifecycle.avg_image_age_days}\n"
            f"  - nightly_scheduled_pipeline_found: {pd.nightly_build.scheduled_pipeline_found}\n"
            f"  - dependency_automated_prs_merged: {pd.dependency_automation.automated_prs_merged_count}\n"
            f"  - limitation_note: {pd.image_lifecycle.limitation_note}\n"
        )
        result = await _async_llm(LEVEL4_SYSTEM_PROMPT, summary)
        if "error" in result:
            return {"status": "error", "error_message": result["error"], "stop_assessment": True}

        level_results = dict(state.get("level_results", {}))
        level_results[4] = result

        if result.get("passed"):
            return {"level_results": level_results, "current_level": 4, "stop_assessment": False}
        return {
            "level_results": level_results,
            "current_level": 4,
            "final_score": result.get("score", 0.0),
            "stop_assessment": True,
            "status": "assessment_stopped_at_level_4",
        }
    except Exception as exc:
        logger.error("level4_node failed: %s", exc, exc_info=True)
        return {"status": "error", "error_message": str(exc), "stop_assessment": True}


# --------------------------------------------------------------------------- #
# Level 5: Not Applicable (placeholder, auto-pass per Rule 25)
# --------------------------------------------------------------------------- #

async def level5_node(state: dict) -> dict:
    if state.get("stop_assessment"):
        return {}
    logger.info("── level5: START ──")
    level_results = dict(state.get("level_results", {}))
    level_results[5] = {
        "level": 5,
        "passed": True,
        "score": 5.0,
        "passed_criteria": [{"name": "Not Applicable", "reason": "No controls are currently defined for Level 5."}],
        "failed_criteria": [],
        "reasoning": "Level 5 has no assessment controls defined; auto-passed as Not Applicable.",
        "recommendations": [],
    }
    return {
        "level_results": level_results,
        "current_level": 5,
        "final_score": 5.0,
        "stop_assessment": False,
    }


# --------------------------------------------------------------------------- #
# Terminal node: format_result
# --------------------------------------------------------------------------- #

ALL_LEVELS = [1, 2, 3, 4, 5]


async def format_result_node(state: dict) -> dict:
    logger.info("── format_result: START ──")
    level_results: dict = state.get("level_results", {})
    current_level = state.get("current_level", 0)
    error_message = state.get("error_message")
    result_id = state.get("result_id")
    platform_data = state.get("platform_data")

    # Find the first failing level, if any, for skip-reason text.
    failed_at_level = None
    for lvl in ALL_LEVELS:
        if lvl in level_results and not level_results[lvl].get("passed", True):
            failed_at_level = lvl
            break

    # Highest passed level determines maturity_level / final score.
    if error_message:
        maturity_level = 0
        final_score = 0.0
    else:
        passed_levels = [lvl for lvl in ALL_LEVELS if lvl in level_results and level_results[lvl].get("passed")]
        maturity_level = max(passed_levels) if passed_levels else 0
        if failed_at_level is not None:
            final_score = level_results[failed_at_level].get("score", 0.0)
        elif maturity_level:
            final_score = level_results[maturity_level].get("score", 0.0)
        else:
            final_score = 0.0

    level_wise_criteria = []
    assessment = {}
    missing_controls = []
    all_recommendations = []

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
                missing_controls.append({"level": lvl, "control": name, "reason": reason})

            status_str = "PASSED" if res.get("passed") else "FAILED"
            level_wise_criteria.append({
                "level": lvl,
                "level_name": lvl_name,
                "status": status_str,
                "checked": True,
                "score": res.get("score"),
                "reasoning": res.get("reasoning", ""),
                "criteria": criteria_list,
            })
            assessment[f"level_{lvl}"] = {
                "status": "PASS" if res.get("passed") else "FAIL",
                "controls": criteria_list,
            }
            for rec in res.get("recommendations", []):
                all_recommendations.append({"level": lvl, **rec})
        else:
            if failed_at_level:
                failed_name = LEVEL_DESCRIPTIONS.get(failed_at_level, f"Level {failed_at_level}")
                skip_reason = (
                    f"Level {failed_at_level} ({failed_name}) did not pass — "
                    f"assessment halted before reaching this level."
                )
            elif error_message:
                skip_reason = f"Assessment halted due to an error: {error_message}"
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
                    {"name": c, "status": "NOT_CHECKED", "reason": skip_reason}
                    for c in canonical
                ],
            })
            assessment[f"level_{lvl}"] = {"status": "NOT_CHECKED", "controls": []}

    level_breakdown = {
        str(lvl): {
            "passed": level_results[lvl].get("passed", False),
            "score": level_results[lvl].get("score"),
        }
        for lvl in ALL_LEVELS
        if lvl in level_results
    }

    limitations = []
    if platform_data is not None:
        if not platform_data.attack_surface.inspection_possible:
            limitations.append(platform_data.attack_surface.limitation_note)
        if not platform_data.image_lifecycle.registry_accessible:
            limitations.append(platform_data.image_lifecycle.limitation_note)

    status = "ERROR" if error_message else f"FAILED_AT_LEVEL_{failed_at_level}" if failed_at_level else "COMPLETED"
    summary = (
        f"Assessment failed: {error_message}" if error_message else
        f"Patch management maturity assessed at Level {maturity_level}."
        + (f" Stopped at Level {failed_at_level} due to unmet controls." if failed_at_level else " All defined levels passed.")
    )

    final_result = {
        "workflow": "patch_management",
        "maturity_level": maturity_level,
        "score": round(final_score, 2),
        "status": status,
        "summary": summary,
        "assessment": assessment,
        "missing_controls": missing_controls,
        "recommendations": all_recommendations,
        "limitations": limitations,
        "level_wise_criteria": level_wise_criteria,
        "level_breakdown": level_breakdown,
        "platform": {
            "platform_type": platform_data.platform_type if platform_data else None,
            "repository": platform_data.repository if platform_data else None,
            "api_call_log": platform_data.api_call_log if platform_data else [],
        },
    }

    try:
        from core.database import SessionLocal
        from core.repositories.assessment_result_repository import AssessmentResultRepository

        db = SessionLocal()
        try:
            if result_id:
                AssessmentResultRepository.update_assessment_result(
                    db=db,
                    result_id=result_id,
                    status="FAILED" if error_message else "COMPLETED",
                    domain_score=final_score,
                    reasoning=summary,
                    improvement_recommendations=all_recommendations,
                    additional_info=final_result,
                )
        finally:
            db.close()
    except Exception as db_exc:
        logger.error("Failed to persist final assessment result: %s", db_exc)

    logger.info("── format_result: result=%s ──", status)
    return {"final_result": final_result, "status": "completed"}
