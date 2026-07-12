"""
Node functions for the Dynamic_Depth_for_Infrastructure workflow.
"""

import json
import re

from core.logger import get_logger
from core.llm_provider import LLMProvider
from langchain_core.messages import HumanMessage, SystemMessage

from workflows.Dynamic_Depth_for_Infrastructure.config import (
    LEVEL2_SYSTEM_PROMPT,
    LEVEL3_SYSTEM_PROMPT,
    LEVEL4_SYSTEM_PROMPT,
    LEVEL5_SYSTEM_PROMPT,
    LEVEL_CRITERIA_NAMES,
    LEVEL_DESCRIPTIONS,
)
from workflows.Dynamic_Depth_for_Infrastructure.connectors import (
    CLOUD_CONNECTOR_REGISTRY,
    SCM_CONNECTOR_REGISTRY,
)

logger = get_logger(__name__)

ALL_LEVELS = [1, 2, 3, 4, 5]


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
                domain_name="Dynamic_Depth_for_Infrastructure",
            )
        finally:
            db.close()
    except Exception as db_exc:
        logger.error("Failed to insert IN_PROGRESS record: %s", db_exc)

    source_platform = state.get("source_platform", "")
    cloud_platform = state.get("cloud_platform", "")
    credentials = state.get("credentials", {})
    repository = credentials.get("repository", "")

    scm_connector_cls = SCM_CONNECTOR_REGISTRY.get(source_platform)
    if scm_connector_cls is None:
        return {
            "status": "error",
            "error_message": f"Unsupported source_platform '{source_platform}'.",
            "stop_assessment": True,
            "result_id": result_id,
        }

    try:
        scm_connector = scm_connector_cls(credentials)
        healthy = await scm_connector.health_check()
        if not healthy:
            return {
                "status": "error",
                "error_message": "SCM authentication failed or platform unreachable.",
                "stop_assessment": True,
                "result_id": result_id,
            }

        platform_data = await scm_connector.collect_pipeline_evidence(repository)

        # Optionally enrich with cloud evidence
        cloud_connector_cls = CLOUD_CONNECTOR_REGISTRY.get(cloud_platform)
        if cloud_connector_cls:
            try:
                cloud_connector = cloud_connector_cls(credentials)
                cloud_healthy = await cloud_connector.health_check()
                if cloud_healthy:
                    platform_data = await cloud_connector.enrich_with_cloud_evidence(platform_data)
                else:
                    logger.warning("Cloud connector health check failed — skipping cloud enrichment")
            except Exception as cloud_exc:
                logger.warning("Cloud enrichment failed: %s", cloud_exc)

        platform_data.cloud_platform_type = cloud_platform
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
# Level 1: Baseline — auto-pass
# --------------------------------------------------------------------------- #

async def level1_node(state: dict) -> dict:
    if state.get("stop_assessment"):
        return {}
    logger.info("── level1: START ──")
    level_results = dict(state.get("level_results", {}))
    level_results[1] = {
        "level": 1,
        "passed": True,
        "score": 1.0,
        "passed_checks": ["Baseline"],
        "failed_checks": [],
        "reason": ["Level 1 is the baseline entry level — all applications start here."],
        "recommendations": [],
        "improvement_actions": [],
    }
    return {"level_results": level_results, "current_level": 1, "stop_assessment": False}


# --------------------------------------------------------------------------- #
# Level 2: Exposed Services, Network Segmentation, Cloud Configuration
# --------------------------------------------------------------------------- #

async def level2_node(state: dict) -> dict:
    if state.get("stop_assessment"):
        return {}
    logger.info("── level2: START ──")
    try:
        pd = state["platform_data"]
        es = pd.exposed_services
        ns = pd.network_segmentation
        cc = pd.cloud_configuration
        summary = (
            f"Test for Exposed Services evidence:\n"
            f"  - exposed_services_scan_found: {es.exposed_services_scan_found}\n"
            f"  - port_scanning_configured: {es.port_scanning_configured}\n"
            f"  - subdomain_enumeration_found: {es.subdomain_enumeration_found}\n"
            f"  - kubernetes_exposure_checked: {es.kubernetes_exposure_checked}\n"
            f"  - scan_in_pipeline: {es.scan_in_pipeline}\n"
            f"  - tools_detected: {es.tools_detected}\n\n"
            f"Test Network Segmentation evidence:\n"
            f"  - network_segmentation_configured: {ns.network_segmentation_configured}\n"
            f"  - pod_isolation_configured: {ns.pod_isolation_configured}\n"
            f"  - firewall_rules_found: {ns.firewall_rules_found}\n"
            f"  - network_policies_found: {ns.network_policies_found}\n"
            f"  - nsg_rules_found: {ns.nsg_rules_found}\n"
            f"  - tools_detected: {ns.tools_detected}\n\n"
            f"Test Cloud Configuration evidence:\n"
            f"  - storage_config_checked: {cc.storage_config_checked}\n"
            f"  - iam_config_checked: {cc.iam_config_checked}\n"
            f"  - security_groups_checked: {cc.security_groups_checked}\n"
            f"  - logging_enabled: {cc.logging_enabled}\n"
            f"  - monitoring_enabled: {cc.monitoring_enabled}\n"
            f"  - encryption_configured: {cc.encryption_configured}\n"
            f"  - misconfiguration_scan_found: {cc.misconfiguration_scan_found}\n"
            f"  - tools_detected: {cc.tools_detected}\n"
            f"  - limitation_note: {cc.limitation_note}\n"
        )
        result = await _async_llm(LEVEL2_SYSTEM_PROMPT, summary)

        print("\n========== LEVEL 2 LLM RESULT ==========")
        print(result)
        print("========================================")

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
# Level 3: Unauthorized Installation, Weak Password
# --------------------------------------------------------------------------- #

async def level3_node(state: dict) -> dict:
    if state.get("stop_assessment"):
        return {}
    logger.info("── level3: START ──")
    try:
        pd = state["platform_data"]
        ui = pd.unauthorized_installation
        wp = pd.weak_password
        summary = (
            f"Unauthorized Installation Test evidence:\n"
            f"  - approved_images_policy_found: {ui.approved_images_policy_found}\n"
            f"  - base_image_verification_found: {ui.base_image_verification_found}\n"
            f"  - image_whitelisting_configured: {ui.image_whitelisting_configured}\n"
            f"  - unauthorized_container_detection: {ui.unauthorized_container_detection}\n"
            f"  - cluster_scanning_found: {ui.cluster_scanning_found}\n"
            f"  - docker_image_validation_found: {ui.docker_image_validation_found}\n"
            f"  - tools_detected: {ui.tools_detected}\n\n"
            f"Weak Password Test evidence:\n"
            f"  - default_accounts_check: {wp.default_accounts_check}\n"
            f"  - weak_password_scan_found: {wp.weak_password_scan_found}\n"
            f"  - brute_force_protection_found: {wp.brute_force_protection_found}\n"
            f"  - password_policy_found: {wp.password_policy_found}\n"
            f"  - mfa_configured: {wp.mfa_configured}\n"
            f"  - tools_detected: {wp.tools_detected}\n"
            f"  - limitation_note: {wp.limitation_note}\n"
        )
        result = await _async_llm(LEVEL3_SYSTEM_PROMPT, summary)

        print("\n========== LEVEL 3 LLM RESULT ==========")
        print(result)
        print("========================================")

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
# Level 4: Load Testing
# --------------------------------------------------------------------------- #

async def level4_node(state: dict) -> dict:
    if state.get("stop_assessment"):
        return {}
    logger.info("── level4: START ──")
    try:
        pd = state["platform_data"]
        lt = pd.load_testing
        summary = (
            f"Load Testing evidence:\n"
            f"  - load_testing_configured: {lt.load_testing_configured}\n"
            f"  - production_load_test_found: {lt.production_load_test_found}\n"
            f"  - performance_benchmarking_found: {lt.performance_benchmarking_found}\n"
            f"  - stress_testing_found: {lt.stress_testing_found}\n"
            f"  - capacity_validation_found: {lt.capacity_validation_found}\n"
            f"  - tools_detected: {lt.tools_detected}\n"
            f"  - examples: {lt.examples}\n"
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
# Level 5: Unused Resources
# --------------------------------------------------------------------------- #

async def level5_node(state: dict) -> dict:
    if state.get("stop_assessment"):
        return {}
    logger.info("── level5: START ──")
    try:
        pd = state["platform_data"]
        ur = pd.unused_resources
        summary = (
            f"Unused Resources evidence:\n"
            f"  - idle_vm_scan_found: {ur.idle_vm_scan_found}\n"
            f"  - unused_storage_scan_found: {ur.unused_storage_scan_found}\n"
            f"  - unattached_disk_scan_found: {ur.unattached_disk_scan_found}\n"
            f"  - unused_public_ip_scan_found: {ur.unused_public_ip_scan_found}\n"
            f"  - idle_load_balancer_scan_found: {ur.idle_load_balancer_scan_found}\n"
            f"  - unused_kubernetes_resources_scan: {ur.unused_kubernetes_resources_scan}\n"
            f"  - orphaned_resources_scan_found: {ur.orphaned_resources_scan_found}\n"
            f"  - tools_detected: {ur.tools_detected}\n"
            f"  - limitation_note: {ur.limitation_note}\n"
        )
        result = await _async_llm(LEVEL5_SYSTEM_PROMPT, summary)
        if "error" in result:
            return {"status": "error", "error_message": result["error"], "stop_assessment": True}

        level_results = dict(state.get("level_results", {}))
        level_results[5] = result

        if result.get("passed"):
            return {
                "level_results": level_results,
                "current_level": 5,
                "final_score": result.get("score", 5.0),
                "stop_assessment": False,
            }
        return {
            "level_results": level_results,
            "current_level": 5,
            "final_score": result.get("score", 0.0),
            "stop_assessment": True,
            "status": "assessment_stopped_at_level_5",
        }
    except Exception as exc:
        logger.error("level5_node failed: %s", exc, exc_info=True)
        return {"status": "error", "error_message": str(exc), "stop_assessment": True}


# --------------------------------------------------------------------------- #
# Terminal node: format_result
# --------------------------------------------------------------------------- #

async def format_result_node(state: dict) -> dict:
    logger.info("── format_result: START ──")
    level_results: dict = state.get("level_results", {})
    error_message = state.get("error_message")
    result_id = state.get("result_id")
    platform_data = state.get("platform_data")

    failed_at_level = None
    for lvl in ALL_LEVELS:
        if lvl in level_results and not level_results[lvl].get("passed", True):
            failed_at_level = lvl
            break

    if error_message:
        maturity_level = 0
        final_score = 0.0
    else:
        passed_levels = [
            lvl
            for lvl in ALL_LEVELS
            if lvl in level_results and level_results[lvl].get("passed")
        ]

        if failed_at_level is not None:
            maturity_level = failed_at_level
            final_score = level_results[failed_at_level].get("score", 0.0)
        else:
            maturity_level = max(passed_levels) if passed_levels else 0

            if maturity_level:
                final_score = level_results[maturity_level].get("score", 0.0)
            else:
                final_score = 0.0

    all_passed_checks = []
    all_failed_checks = []
    all_reasons = []
    all_recommendations = []
    all_improvement_actions = []
    level_wise_criteria = []

    for lvl in ALL_LEVELS:
        lvl_name = LEVEL_DESCRIPTIONS.get(lvl, f"Level {lvl}")
        if lvl in level_results:
            res = level_results[lvl]
            all_passed_checks.extend(res.get("passed_checks", []))
            all_failed_checks.extend(res.get("failed_checks", []))
            all_reasons.extend(res.get("reason", []))
            all_recommendations.extend(res.get("recommendations", []))
            all_improvement_actions.extend(res.get("improvement_actions", []))

            criteria_list = []
            for c in res.get("passed_checks", []):
                criteria_list.append({"name": c, "status": "PASSED", "reason": ""})
            for c in res.get("failed_checks", []):
                criteria_list.append({"name": c, "status": "FAILED", "reason": ""})

            level_wise_criteria.append({
                "level": lvl,
                "level_name": lvl_name,
                "status": "PASSED" if res.get("passed") else "FAILED",
                "checked": True,
                "score": res.get("score"),
                "reasoning": " | ".join(res.get("reason", [])),
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
                "criteria": [
                    {"name": c, "status": "NOT_CHECKED", "reason": skip_reason}
                    for c in canonical
                ],
            })

    level_breakdown = {
        str(lvl): {
            "passed": level_results[lvl].get("passed", False),
            "score": level_results[lvl].get("score"),
        }
        for lvl in ALL_LEVELS
        if lvl in level_results
    }

    status = (
        "ERROR" if error_message else
        f"Failed at Level {failed_at_level}" if failed_at_level else
        "COMPLETED"
    )

    next_maturity_level = (failed_at_level or maturity_level + 1) if maturity_level < 5 else None

    final_result = {
        "workflow_name": "Dynamic_Depth_for_Infrastructure",
        "maturity_level": maturity_level,
        "score": round(final_score, 2),
        "status": status,
        "reason": all_reasons,
        "passed_checks": list(dict.fromkeys(all_passed_checks)),
        "failed_checks": list(dict.fromkeys(all_failed_checks)),
        "recommendations": list(dict.fromkeys(all_recommendations)),
        "improvement_actions": list(dict.fromkeys(all_improvement_actions)),
        "next_maturity_level": next_maturity_level,
        "level_wise_criteria": level_wise_criteria,
        "level_breakdown": level_breakdown,
        "platform": {
            "source_platform_type": platform_data.source_platform_type if platform_data else None,
            "cloud_platform_type": platform_data.cloud_platform_type if platform_data else None,
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
                    reasoning=" | ".join(all_reasons),
                    improvement_recommendations=all_recommendations,
                    additional_info=final_result,
                )
        finally:
            db.close()
    except Exception as db_exc:
        logger.error("Failed to persist final result: %s", db_exc)

    logger.info("── format_result: result=maturity_level=%d score=%.2f ──", maturity_level, final_score)
    return {"final_result": final_result, "status": "completed"}
