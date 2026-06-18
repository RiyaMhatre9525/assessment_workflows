import json
import re
from core.logger import get_logger
from core.llm_provider import LLMProvider
from langchain_core.messages import HumanMessage, SystemMessage
from workflows.deployment_domain.connectors import CONNECTOR_REGISTRY
from workflows.deployment_domain.connectors.base import DeploymentPlatformData
from workflows.deployment_domain.config import (
    LEVEL_SCORE_RANGES,
    LEVEL_DESCRIPTIONS,
    LEVEL1_SYSTEM_PROMPT,
    LEVEL2_SYSTEM_PROMPT,
    LEVEL3_SYSTEM_PROMPT,
    LEVEL4_SYSTEM_PROMPT,
    LEVEL5_SYSTEM_PROMPT,
)

logger = get_logger(__name__)


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


def _build_platform_summary(pd: DeploymentPlatformData) -> str:
    lines = [
        f"Platform: {pd.platform_type}",
        f"Repository: {pd.repository}",
        f"Pipelines found: {len(pd.pipelines)}",
    ]
    for p in pd.pipelines:
        lines.append(
            f"  - [{p.name}] deploy={p.has_deployment_job} rollback={p.has_rollback_step} "
            f"approval={p.has_approval_gate} iac={p.uses_iac}"
        )
    lines += [
        f"Artifacts found: {len(pd.artifacts)}",
        f"Secrets tool: {pd.secrets.tool_detected or 'none'} | externalized={pd.secrets.secrets_externalized} | encrypted={pd.secrets.env_config_encrypted}",
        f"Decommissioning documented: {pd.decommissioning.process_documented} | containers={pd.decommissioning.covers_containers} | k8s={pd.decommissioning.covers_kubernetes}",
        f"Dependency tracking tool: {pd.dependencies.tracking_tool_detected or 'none'} | vulns tracked={pd.dependencies.vulnerabilities_tracked}",
        f"Zero-downtime strategy: {pd.zero_downtime.strategy or 'none'} | rolling={pd.zero_downtime.rolling_update_detected} | blue_green={pd.zero_downtime.blue_green_detected}",
        f"Feature flags detected: {pd.feature_toggles.feature_flags_detected} | env-var toggles={pd.feature_toggles.env_var_toggles}",
        f"Same artifact across envs: {pd.same_artifact_across_envs}",
        f"API calls made: {len(pd.api_call_log)}",
    ]
    return "\n".join(lines)


async def collect_platform_data_node(state: dict) -> dict:
    logger.info("── collect_platform_data_node: START ──")
    try:
        platform_type = state["platform_type"]
        repository = state.get("repository", "")
        credentials = state.get("credentials", {})

        connector_cls = CONNECTOR_REGISTRY.get(platform_type)
        if not connector_cls:
            return {
                "status": "error",
                "error_message": f"Unsupported platform: {platform_type}",
                "stop_assessment": True,
            }

        connector = connector_cls(credentials)

        healthy = await connector.health_check()
        if not healthy:
            return {
                "status": "error",
                "error_message": f"Authentication failed for platform: {platform_type}",
                "stop_assessment": True,
            }

        platform_data = await connector.collect(repository)
        logger.info("── collect_platform_data_node: collected %d pipelines ──", len(platform_data.pipelines))
        return {"platform_data": platform_data, "status": "data_collected", "stop_assessment": False}

    except Exception as exc:
        logger.error("collect_platform_data_node failed: %s", exc, exc_info=True)
        return {"status": "error", "error_message": str(exc), "stop_assessment": True}


async def level1_node(state: dict) -> dict:
    logger.info("── level1_node: START ──")
    if state.get("stop_assessment"):
        return {}
    try:
        summary = _build_platform_summary(state["platform_data"])
        result = await _call_llm_json(LEVEL1_SYSTEM_PROMPT, summary)

        level_results = dict(state.get("level_results") or {})
        level_results["1"] = {"passed": result.get("passed"), "score": result.get("score")}

        if not result.get("passed"):
            return {
                "level_results": level_results,
                "current_level": 1,
                "final_score": result.get("score", LEVEL_SCORE_RANGES[1][0]),
                "stop_assessment": True,
                "last_level_detail": result,
                "status": "assessment_stopped_at_level_1",
            }
        return {
            "level_results": level_results,
            "current_level": 1,
            "last_level_detail": result,
            "stop_assessment": False,
        }
    except Exception as exc:
        logger.error("level1_node failed: %s", exc, exc_info=True)
        return {"error_message": str(exc), "stop_assessment": True}


async def level2_node(state: dict) -> dict:
    logger.info("── level2_node: START ──")
    if state.get("stop_assessment"):
        return {}
    try:
        summary = _build_platform_summary(state["platform_data"])
        result = await _call_llm_json(LEVEL2_SYSTEM_PROMPT, summary)

        level_results = dict(state.get("level_results") or {})
        level_results["2"] = {"passed": result.get("passed"), "score": result.get("score")}

        if not result.get("passed"):
            return {
                "level_results": level_results,
                "current_level": 2,
                "final_score": result.get("score", LEVEL_SCORE_RANGES[2][0]),
                "stop_assessment": True,
                "last_level_detail": result,
                "status": "assessment_stopped_at_level_2",
            }
        return {
            "level_results": level_results,
            "current_level": 2,
            "last_level_detail": result,
            "stop_assessment": False,
        }
    except Exception as exc:
        logger.error("level2_node failed: %s", exc, exc_info=True)
        return {"error_message": str(exc), "stop_assessment": True}


async def level3_node(state: dict) -> dict:
    logger.info("── level3_node: START ──")
    if state.get("stop_assessment"):
        return {}
    try:
        summary = _build_platform_summary(state["platform_data"])
        result = await _call_llm_json(LEVEL3_SYSTEM_PROMPT, summary)

        level_results = dict(state.get("level_results") or {})
        level_results["3"] = {"passed": result.get("passed"), "score": result.get("score")}

        if not result.get("passed"):
            return {
                "level_results": level_results,
                "current_level": 3,
                "final_score": result.get("score", LEVEL_SCORE_RANGES[3][0]),
                "stop_assessment": True,
                "last_level_detail": result,
                "status": "assessment_stopped_at_level_3",
            }
        return {
            "level_results": level_results,
            "current_level": 3,
            "last_level_detail": result,
            "stop_assessment": False,
        }
    except Exception as exc:
        logger.error("level3_node failed: %s", exc, exc_info=True)
        return {"error_message": str(exc), "stop_assessment": True}


async def level4_node(state: dict) -> dict:
    logger.info("── level4_node: START ──")
    if state.get("stop_assessment"):
        return {}
    try:
        summary = _build_platform_summary(state["platform_data"])
        result = await _call_llm_json(LEVEL4_SYSTEM_PROMPT, summary)

        level_results = dict(state.get("level_results") or {})
        level_results["4"] = {"passed": result.get("passed"), "score": result.get("score")}

        if not result.get("passed"):
            return {
                "level_results": level_results,
                "current_level": 4,
                "final_score": result.get("score", LEVEL_SCORE_RANGES[4][0]),
                "stop_assessment": True,
                "last_level_detail": result,
                "status": "assessment_stopped_at_level_4",
            }
        return {
            "level_results": level_results,
            "current_level": 4,
            "last_level_detail": result,
            "stop_assessment": False,
        }
    except Exception as exc:
        logger.error("level4_node failed: %s", exc, exc_info=True)
        return {"error_message": str(exc), "stop_assessment": True}


async def level5_node(state: dict) -> dict:
    logger.info("── level5_node: START ──")
    if state.get("stop_assessment"):
        return {}
    try:
        summary = _build_platform_summary(state["platform_data"])
        result = await _call_llm_json(LEVEL5_SYSTEM_PROMPT, summary)

        level_results = dict(state.get("level_results") or {})
        level_results["5"] = {"passed": result.get("passed"), "score": result.get("score")}

        # Level 5 always terminates — pass or fail it's the final level
        final_score = result.get("score", LEVEL_SCORE_RANGES[5][0])
        return {
            "level_results": level_results,
            "current_level": 5,
            "final_score": final_score,
            "stop_assessment": True,
            "last_level_detail": result,
            "status": "assessment_completed_level_5",
        }
    except Exception as exc:
        logger.error("level5_node failed: %s", exc, exc_info=True)
        return {"error_message": str(exc), "stop_assessment": True}


async def format_result_node(state: dict) -> dict:
    logger.info("── format_result_node: START ──")
    try:
        level_results = state.get("level_results") or {}
        current_level = state.get("current_level", 0)
        final_score = state.get("final_score", 0.0)
        detail = state.get("last_level_detail") or {}
        error_message = state.get("error_message", "")

        if error_message and not detail:
            final_result = {
                "maturity_level": current_level,
                "score": final_score,
                "score_range": f"{LEVEL_SCORE_RANGES.get(current_level, (0.0, 1.0))[0]}–{LEVEL_SCORE_RANGES.get(current_level, (0.0, 1.0))[1]}",
                "assessment_details": {
                    "passed_criteria": [],
                    "failed_criteria": [],
                    "reasoning": f"Assessment error: {error_message}",
                },
                "improvement_recommendations": [],
                "level_breakdown": level_results,
                "api_call_log": getattr(state.get("platform_data"), "api_call_log", []),
            }
        else:
            score_range = LEVEL_SCORE_RANGES.get(current_level, (0.0, 1.0))
            all_recommendations = []
            for rec in detail.get("recommendations", []):
                all_recommendations.append({
                    "gap": rec.get("gap", ""),
                    "action": rec.get("action", ""),
                    "priority": rec.get("priority", "medium"),
                    "estimated_effort": rec.get("estimated_effort", "medium"),
                })

            final_result = {
                "maturity_level": current_level,
                "score": final_score,
                "score_range": f"{score_range[0]}–{score_range[1]}",
                "assessment_details": {
                    "passed_criteria": detail.get("passed_criteria", []),
                    "failed_criteria": detail.get("failed_criteria", []),
                    "reasoning": detail.get("reasoning", ""),
                },
                "improvement_recommendations": all_recommendations,
                "level_breakdown": level_results,
                "api_call_log": getattr(state.get("platform_data"), "api_call_log", []),
            }

        # Persist to database
        assessment_id = state.get("assessment_id")
        if assessment_id:
            try:
                import uuid
                from core.database import SessionLocal
                from core.repositories.assessment_result_repository import AssessmentResultRepository
                db = SessionLocal()
                try:
                    AssessmentResultRepository.insert_assessment_result(
                        db=db,
                        # id=str(uuid.uuid4()),
                        assessment_id=assessment_id,
                        status="COMPLETED",
                        domain_name="DEPLOYMENT",
                        domain_score=float(final_score),
                        reasoning=final_result["assessment_details"]["reasoning"],
                        improvement_recommendations=final_result["improvement_recommendations"],
                        additional_info=final_result,
                    )
                finally:
                    db.close()
            except Exception as db_exc:
                logger.error("format_result_node: DB persist failed: %s", db_exc)

        logger.info("── format_result_node: level=%d score=%.2f ──", current_level, final_score)
        return {"final_result": final_result, "status": "completed"}

    except Exception as exc:
        logger.error("format_result_node failed: %s", exc, exc_info=True)
        return {
            "final_result": {"error": str(exc)},
            "status": "error",
        }
