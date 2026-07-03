"""
LangGraph node functions for the application_hardening workflow.

Node order: collect_platform_data -> level1 -> level2 -> level3 -> level4
-> level5 -> format_result. Each level node is fail-fast: if a level fails,
stop_assessment is set and all subsequent level nodes short-circuit,
falling through to format_result_node which is always terminal.
"""
import json
import re

from langchain_core.messages import HumanMessage, SystemMessage

from core.llm_provider import LLMProvider
from core.logger import get_logger

from .config import (
    LEVEL_CRITERIA_NAMES,
    LEVEL_DESCRIPTIONS,
    LEVEL_SCORE_RANGES,
    LEVEL1_SYSTEM_PROMPT,
    LEVEL2_SYSTEM_PROMPT,
    LEVEL3_SYSTEM_PROMPT,
    LEVEL4_SYSTEM_PROMPT,
    LEVEL5_SYSTEM_PROMPT,
)
from .connectors import CLOUD_CONNECTOR_REGISTRY, VCS_CONNECTOR_REGISTRY
from .connectors.base import ApplicationSecurityData

logger = get_logger(__name__)

LEVEL_PROMPTS = {
    1: LEVEL1_SYSTEM_PROMPT,
    2: LEVEL2_SYSTEM_PROMPT,
    3: LEVEL3_SYSTEM_PROMPT,
    4: LEVEL4_SYSTEM_PROMPT,
    5: LEVEL5_SYSTEM_PROMPT,
}

ALL_LEVELS = [1, 2, 3, 4, 5]


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

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


def _parse_criterion(item) -> tuple[str, str]:
    if isinstance(item, dict):
        return item.get("name", ""), item.get("reason", "")
    return item, ""


def _build_summary(platform_data: ApplicationSecurityData) -> str:
    vcs = platform_data.vcs_data
    cloud = platform_data.cloud_data
    return json.dumps({
        "vcs_platform_type": vcs.vcs_platform_type,
        "repository": vcs.repository,
        "output_encoding": {
            "frameworks_detected": [
                {"name": f.name, "detected": f.detected, "safe_default_rendering": f.safe_default_rendering}
                for f in vcs.output_encoding.frameworks_detected
            ],
            "encoding_library_detected": vcs.output_encoding.encoding_library_detected,
            "csp_header_present": vcs.output_encoding.csp_header_present,
        },
        "input_validation": {
            "parametrized_queries_detected": vcs.input_validation.parametrized_queries_detected,
            "orm_tool_detected": vcs.input_validation.orm_tool_detected,
            "raw_query_concatenation_found": vcs.input_validation.raw_query_concatenation_found,
        },
        "asvs_code_side": {
            "l1_percentage": vcs.asvs_l1_code.percentage,
            "l2_percentage": vcs.asvs_l2_code.percentage,
            "l3_percentage": vcs.asvs_l3_code.percentage,
        },
        "cloud_platform_type": cloud.cloud_platform_type,
        "resource_scope": cloud.resource_scope,
        "container_security": {
            "images_scanned": cloud.container_security.images_scanned,
            "non_root_enforced_count": cloud.container_security.non_root_enforced_count,
            "root_images": cloud.container_security.root_images,
            "enforcement_method": cloud.container_security.enforcement_method,
        },
        "security_headers": {
            "endpoints_checked": cloud.security_headers.endpoints_checked,
            "server_header_hidden": cloud.security_headers.server_header_hidden,
            "powered_by_header_removed": cloud.security_headers.powered_by_header_removed,
            "deployment_method": cloud.security_headers.deployment_method,
            "headers_present": cloud.security_headers.headers_present,
        },
        "asvs_infra_side": {
            "l1_percentage": cloud.asvs_l1_infra.percentage,
            "l2_percentage": cloud.asvs_l2_infra.percentage,
            "l3_percentage": cloud.asvs_l3_infra.percentage,
        },
    }, default=str)


async def _run_level_node(level: int, state: dict) -> dict:
    if state.get("stop_assessment"):
        return {}

    logger.info("── level%d_node: START ──", level)
    try:
        platform_data: ApplicationSecurityData = state["platform_data"]
        summary = _build_summary(platform_data)
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
        score = result.get("score", LEVEL_SCORE_RANGES[level][0])
        logger.info("── level%d_node: result=passed=%s score=%s ──", level, passed, score)

        is_last_level = level == ALL_LEVELS[-1]
        if passed and not is_last_level:
            return {
                "level_results": level_results,
                "current_level": level,
                "final_score": score,
                "stop_assessment": False,
            }
        else:
            # Either failed, or this was the last level — assessment concludes here.
            return {
                "level_results": level_results,
                "current_level": level,
                "final_score": score,
                "stop_assessment": True,
                "status": f"assessment_{'completed' if passed else 'stopped'}_at_level_{level}",
            }
    except Exception as exc:
        logger.error("level%d_node failed: %s", level, exc, exc_info=True)
        return {
            "status": "error",
            "error_message": str(exc),
            "stop_assessment": True,
            "current_level": level,
        }


# --------------------------------------------------------------------------
# Node 0: collect platform data
# --------------------------------------------------------------------------

async def collect_platform_data_node(state: dict) -> dict:
    logger.info("── collect_platform_data_node: START ──")
    from core.database import SessionLocal
    from core.repositories.assessment_result_repository import AssessmentResultRepository

    result_id = None
    db = SessionLocal()
    try:
        result_id = AssessmentResultRepository.insert_assessment_result_returning_id(
            db=db,
            assessment_id=state["assessment_id"],
            status="IN_PROGRESS",
            domain_name="application_hardening",
        )
    except Exception as exc:
        logger.error("Failed to insert IN_PROGRESS assessment result: %s", exc, exc_info=True)
    finally:
        db.close()

    try:
        vcs_type = state["vcs_platform_type"]
        cloud_type = state["cloud_platform_type"]

        vcs_connector_cls = VCS_CONNECTOR_REGISTRY.get(vcs_type)
        cloud_connector_cls = CLOUD_CONNECTOR_REGISTRY.get(cloud_type)

        if not vcs_connector_cls:
            return {
                "status": "error",
                "error_message": f"Unsupported vcs_platform_type: {vcs_type}",
                "stop_assessment": True,
                "result_id": result_id,
            }
        if not cloud_connector_cls:
            return {
                "status": "error",
                "error_message": f"Unsupported cloud_platform_type: {cloud_type}",
                "stop_assessment": True,
                "result_id": result_id,
            }

        vcs_connector = vcs_connector_cls(state["vcs_credentials"])
        cloud_connector = cloud_connector_cls(state["cloud_credentials"])

        if not await vcs_connector.health_check():
            return {
                "status": "error",
                "error_message": f"Health check failed for VCS platform '{vcs_type}'",
                "stop_assessment": True,
                "result_id": result_id,
            }
        if not await cloud_connector.health_check():
            return {
                "status": "error",
                "error_message": f"Health check failed for cloud platform '{cloud_type}'",
                "stop_assessment": True,
                "result_id": result_id,
            }

        vcs_data = await vcs_connector.collect(state["repository"])
        cloud_data = await cloud_connector.collect(state.get("cloud_resource_scope", state["repository"]))

        platform_data = ApplicationSecurityData(vcs_data=vcs_data, cloud_data=cloud_data)

        logger.info("── collect_platform_data_node: data collected ──")
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


# --------------------------------------------------------------------------
# Nodes 1-5: one per maturity level
# --------------------------------------------------------------------------

async def level1_node(state: dict) -> dict:
    return await _run_level_node(1, state)


async def level2_node(state: dict) -> dict:
    return await _run_level_node(2, state)


async def level3_node(state: dict) -> dict:
    return await _run_level_node(3, state)


async def level4_node(state: dict) -> dict:
    return await _run_level_node(4, state)


async def level5_node(state: dict) -> dict:
    return await _run_level_node(5, state)


# --------------------------------------------------------------------------
# Terminal node: always runs
# --------------------------------------------------------------------------

async def format_result_node(state: dict) -> dict:
    logger.info("── format_result_node: START ──")
    from core.database import SessionLocal
    from core.repositories.assessment_result_repository import AssessmentResultRepository

    level_results: dict = state.get("level_results", {})
    current_level: int = state.get("current_level", 0)
    final_score: float = state.get("final_score", 0.0)
    result_id = state.get("result_id")
    error_message = state.get("error_message")

    # Aggregate recommendations from all completed levels.
    all_recommendations = []
    for lvl in ALL_LEVELS:
        if lvl in level_results:
            for rec in level_results[lvl].get("recommendations", []):
                all_recommendations.append(rec)

    # Find first failing level (for skip reasons on NOT_CHECKED levels).
    failed_at_level = None
    for lvl in ALL_LEVELS:
        if lvl in level_results and not level_results[lvl].get("passed", True):
            failed_at_level = lvl
            break

    level_wise_criteria = []
    level_breakdown = {}
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
            level_breakdown[str(lvl)] = {"passed": bool(res.get("passed")), "score": res.get("score")}
        else:
            if error_message and lvl > current_level:
                skip_reason = f"Assessment halted due to an error: {error_message}"
            elif failed_at_level:
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

    # Determine overall maturity level + score.
    maturity_level = current_level if current_level else 0
    score_range = LEVEL_SCORE_RANGES.get(maturity_level, (0.0, 0.0))
    score_range_str = f"{score_range[0]}-{score_range[1]}"

    top_result = level_results.get(current_level, {})
    passed_criteria_top = top_result.get("passed_criteria", [])
    failed_criteria_top = top_result.get("failed_criteria", [])
    reasoning_top = top_result.get("reasoning", error_message or "")

    platform_data: ApplicationSecurityData | None = state.get("platform_data")
    api_call_log = platform_data.api_call_log if platform_data else []

    final_result = {
        "workflow_name": "application_hardening",
        "maturity_level": maturity_level,
        "score": final_score,
        "score_range": score_range_str,
        "assessment_details": {
            "passed_criteria": passed_criteria_top,
            "failed_criteria": failed_criteria_top,
            "reasoning": reasoning_top,
        },
        "improvement_recommendations": all_recommendations,
        "level_wise_criteria": level_wise_criteria,
        "level_breakdown": level_breakdown,
        "platform": {
            "api_call_log": api_call_log,
        },
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
                reasoning=reasoning_top,
                improvement_recommendations=all_recommendations,
                additional_info=final_result,
            )
        except Exception as exc:
            logger.error("Failed to update assessment result: %s", exc, exc_info=True)
        finally:
            db.close()

    logger.info("── format_result_node: result=%s ──", status)
    return {"final_result": final_result, "status": "completed"}
