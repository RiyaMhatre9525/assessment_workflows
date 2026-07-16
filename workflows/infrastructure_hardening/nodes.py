"""
workflows/infrastructure_hardening/nodes.py

Node functions for the infrastructure_hardening assessment graph:
  - collect_platform_data_node : gathers VCS + cloud evidence, opens DB record
  - level1_node .. level5_node : one async node per maturity level
  - format_result_node         : terminal node, always runs, closes DB record

All nodes are async and return ONLY the state keys they change, per
WORKFLOW_TEMPLATE_CONTEXT.md Pattern 1.
"""

import json
import re
from datetime import datetime

from langchain_core.messages import HumanMessage, SystemMessage

from core.llm_provider import LLMProvider
from core.logger import get_logger
from core.database import SessionLocal
from core.repositories.assessment_result_repository import AssessmentResultRepository

from workflows.infrastructure_hardening.config import (
    LEVEL_CRITERIA_NAMES,
    LEVEL_DESCRIPTIONS,
    LEVEL_SCORE_RANGES,
    LEVEL_SYSTEM_PROMPTS,
)
from workflows.infrastructure_hardening.connectors import (
    CLOUD_CONNECTOR_REGISTRY,
    VCS_CONNECTOR_REGISTRY,
)
from workflows.infrastructure_hardening.connectors.base import PlatformData

logger = get_logger(__name__)

ALL_LEVELS = [1, 2, 3, 4, 5]
DOMAIN_NAME = "infrastructure_hardening"


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

async def _call_llm_json(system_prompt: str, user_content: str) -> dict:
    """Pattern 4: async LLM call with JSON-fence stripping."""
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


def _parse_criterion(item) -> tuple[str, str, str]:
    """Parse a {name, reason, evidence} object, falling back gracefully
    for older {name, reason} or flat-string formats."""
    if isinstance(item, dict):
        return item.get("name", ""), item.get("reason", ""), item.get("evidence", "")
    return str(item), "", ""


def _build_platform_summary(platform_data: PlatformData) -> str:
    """Builds a flat evidence summary string from PlatformData for the LLM."""
    ac = platform_data.access_control
    enc = platform_data.encryption
    net = platform_data.network
    infra = platform_data.infrastructure
    bkp = platform_data.backup
    env = platform_data.environment

    return f"""
Version Control Platform: {platform_data.vcs_type}
Cloud Platform: {platform_data.cloud_type}
Repository: {platform_data.repository}

--- Access Control ---
Admin count (privileged role assignments): {ac.admin_count}
MFA enforced for admins: {ac.mfa_enforced_admin_pct}%
MFA enforced for all users: {ac.mfa_enforced_all_pct}%
MFA data source / graph policy state: {platform_data.raw_metadata.get("graph_mfa_policy_state", platform_data.raw_metadata.get("mfa_data_source", "not_checked"))}
Privilege review documented: {ac.privilege_review_documented}
RBAC enabled: {ac.rbac_enabled}
Dedicated security account (e.g. Sentinel): {ac.dedicated_security_account}
Microsoft Sentinel detected: {platform_data.raw_metadata.get("sentinel_detected", "not_checked")}

--- Encryption ---
Edge HTTPS enforced: {enc.edge_https_enforced}
Edge HTTPS evidence source: {platform_data.raw_metadata.get("edge_https_source", "app_services" if platform_data.raw_metadata.get("app_service_count", 0) > 0 else "not_detected")}
Internal mTLS enabled: {enc.internal_mtls_enabled}
Encryption at rest enabled: {enc.encryption_at_rest_enabled} ({enc.disk_encryption_type or "none"})

--- Network ---
Egress filtering enabled: {net.egress_filtering_enabled}
Network isolation enabled: {net.network_isolation_enabled}
WAF mode: {net.waf_mode or "none"}
WAF custom rule count: {net.waf_custom_rule_count}
WAF ML-driven detection: {net.waf_ml_detection}

--- Infrastructure ---
Virtualized environments: {infra.virtualized_environments}
Immutable infrastructure: {infra.immutable_infrastructure}
Infrastructure as Code managed: {infra.iac_managed} ({infra.iac_tool or "n/a"})
Resource limits enforced on VMs: {infra.resource_limits_enforced}
Chaos engineering enabled: {infra.chaos_engineering_enabled}
CIS Kubernetes Benchmark level observed: {infra.cis_bench_level}
System call restrictions enabled: {infra.syscall_restrictions_enabled}

--- Backup ---
Automated backups enabled: {bkp.automated_backups_enabled}
Backup restore tested: {bkp.backup_restore_tested}
Pre-deployment backup: {bkp.pre_deploy_backup}

--- Environment ---
Test/production environments separated: {env.test_env_separate}
Has dedicated prod resource group: {platform_data.raw_metadata.get("has_prod_resource_group", "not_checked")}
Has dedicated test resource group: {platform_data.raw_metadata.get("has_test_resource_group", "not_checked")}
Production-parity local dev environments: {env.prod_parity_local_dev}
Anonymized test data: {env.anonymized_test_data}

--- Raw metadata (counts and signals) ---
{json.dumps({k: v for k, v in platform_data.raw_metadata.items() if k not in ("github_org", "github_branch_protection", "ado_policies", "ado_admin_groups")}, default=str)[:2000]}
""".strip()


# ---------------------------------------------------------------------------
# Node 0: collect platform data (always first)
# ---------------------------------------------------------------------------

async def collect_platform_data_node(state: dict) -> dict:
    logger.info("── collect_platform_data_node: START ──")

    assessment_id = state.get("assessment_id")
    db = SessionLocal()
    try:
        result_id = AssessmentResultRepository.insert_assessment_result_returning_id(
            db=db,
            assessment_id=assessment_id,
            status="IN_PROGRESS",
            domain_name=DOMAIN_NAME,
        )
    except Exception as exc:
        logger.error("Failed to insert IN_PROGRESS assessment record: %s", exc, exc_info=True)
        return {
            "status": "error",
            "error_message": f"Failed to create assessment record: {exc}",
            "stop_assessment": True,
        }
    finally:
        db.close()

    vcs_type = state.get("vcs_type")
    cloud_type = state.get("cloud_type")
    repository = state.get("repository")
    vcs_credentials = state.get("vcs_credentials", {})
    cloud_credentials = state.get("cloud_credentials", {})

    vcs_connector_cls = VCS_CONNECTOR_REGISTRY.get(vcs_type)
    cloud_connector_cls = CLOUD_CONNECTOR_REGISTRY.get(cloud_type)

    if not vcs_connector_cls:
        return {
            "status": "error",
            "error_message": f"Unsupported vcs_type: {vcs_type}",
            "stop_assessment": True,
            "result_id": result_id,
        }
    if not cloud_connector_cls:
        return {
            "status": "error",
            "error_message": f"Unsupported cloud_type: {cloud_type}",
            "stop_assessment": True,
            "result_id": result_id,
        }

    vcs_connector = vcs_connector_cls(vcs_credentials)
    cloud_connector = cloud_connector_cls(cloud_credentials)

    try:
        vcs_ok = await vcs_connector.health_check()
        cloud_ok = await cloud_connector.health_check()
        if not vcs_ok or not cloud_ok:
            failed = []
            if not vcs_ok:
                failed.append(f"vcs:{vcs_type}")
            if not cloud_ok:
                failed.append(f"cloud:{cloud_type}")
            return {
                "status": "error",
                "error_message": f"Health check failed for: {', '.join(failed)}",
                "stop_assessment": True,
                "result_id": result_id,
            }

        platform_data = PlatformData(repository=repository or "")
        platform_data = await vcs_connector.collect(repository, platform_data)
        platform_data = await cloud_connector.collect(repository, platform_data)

    except Exception as exc:
        logger.error("collect_platform_data_node failed: %s", exc, exc_info=True)
        return {
            "status": "error",
            "error_message": str(exc),
            "stop_assessment": True,
            "result_id": result_id,
        }

    return {
        "platform_data": platform_data,
        "status": "data_collected",
        "stop_assessment": False,
        "result_id": result_id,
    }


# ---------------------------------------------------------------------------
# Level nodes 1-5
# ---------------------------------------------------------------------------

async def _run_level_node(state: dict, level: int) -> dict:
    if state.get("stop_assessment"):
        return {}

    logger.info("── level%s_node: START ──", level)
    try:
        platform_data: PlatformData = state["platform_data"]
        summary = _build_platform_summary(platform_data)
        system_prompt = LEVEL_SYSTEM_PROMPTS[level]

        # ── DEBUG: log exactly what evidence text is sent to the LLM ──
        logger.info(
            "── level%s_node: SENDING TO LLM ──\n%s",
            level,
            summary,
        )

        result = await _call_llm_json(system_prompt, summary)

        # ── DEBUG: log the raw LLM response ──
        logger.info(
            "── level%s_node: LLM RESPONSE ── passed=%s score=%s\n%s",
            level,
            result.get("passed"),
            result.get("score"),
            json.dumps(result, indent=2),
        )
        
        if (
            level == 2
            and platform_data.raw_metadata.get("graph_mfa_policy_state")
            == "not_accessible_no_graph_scope"
        ):
            logger.info(
            "FAILED CRITERIA BEFORE FILTER: %s",
            json.dumps(result.get("failed_criteria", []), indent=2),
        )

            result["failed_criteria"] = [
                item
                for item in result.get("failed_criteria", [])
                if item.get("name") != "Universal MFA"
            ]

            result["recommendations"] = [
                item
                for item in result.get("recommendations", [])
                if item.get("gap") != "Universal MFA"
            ]

        if "error" in result:
            return {
                "status": "error",
                "error_message": result["error"],
                "stop_assessment": True,
            }

        level_results = dict(state.get("level_results", {}))
        level_results[level] = result  # store FULL LLM result

        passed = bool(result.get("passed", False))
        score = float(result.get("score", (level - 1)))

        if passed:
            return {
                "level_results": level_results,
                "current_level": level,
                "final_score": score,
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
        logger.error("level%s_node failed: %s", level, exc, exc_info=True)
        return {
            "status": "error",
            "error_message": str(exc),
            "stop_assessment": True,
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


# ---------------------------------------------------------------------------
# Terminal node: always runs
# ---------------------------------------------------------------------------

async def format_result_node(state: dict) -> dict:
    logger.info("── format_result_node: START ──")

    level_results: dict = state.get("level_results", {})
    current_level = state.get("current_level", 0)
    final_score = state.get("final_score", 0.0)
    result_id = state.get("result_id")
    error_message = state.get("error_message")
    platform_data: PlatformData = state.get("platform_data")

    # --- Aggregate recommendations across all completed levels ---
    all_recommendations = []
    for lvl in ALL_LEVELS:
        res = level_results.get(lvl)
        if res:
            all_recommendations.extend(res.get("recommendations", []))

    # --- Find first failing level for skip reason ---
    failed_at_level = None
    for lvl in ALL_LEVELS:
        if lvl in level_results and not level_results[lvl].get("passed", True):
            failed_at_level = lvl
            break

    # --- Build level_wise_criteria for all 5 levels ---
    level_wise_criteria = []
    for lvl in ALL_LEVELS:
        lvl_name = LEVEL_DESCRIPTIONS.get(lvl, f"Level {lvl}")

        if lvl in level_results:
            res = level_results[lvl]
            criteria_list = []
            for item in res.get("passed_criteria", []):
                name, reason, evidence = _parse_criterion(item)
                criteria_list.append({
                    "name": name, "status": "PASSED", "reason": reason, "evidence": evidence,
                })
            for item in res.get("failed_criteria", []):
                name, reason, evidence = _parse_criterion(item)
                criteria_list.append({
                    "name": name, "status": "FAILED", "reason": reason, "evidence": evidence,
                })
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
                    {"name": c, "status": "NOT_CHECKED", "reason": skip_reason, "evidence": ""}
                    for c in canonical
                ],
            })

    # --- Compact level_breakdown ---
    level_breakdown = {
        str(lvl): {"passed": res.get("passed", False), "score": res.get("score")}
        for lvl, res in level_results.items()
    }

    # --- score_range for the achieved level ---
    score_range_tuple = LEVEL_SCORE_RANGES.get(current_level, (0.0, 0.0))
    score_range = f"{score_range_tuple[0]}-{score_range_tuple[1]}"

    # --- Assemble final_result per project output spec ---
    top_level_result = level_results.get(current_level, {})
    final_result = {
        "workflow_name": DOMAIN_NAME,
        "maturity_level": current_level,
        "score": final_score,
        "score_range": score_range,
        "assessment_details": {
            "passed_criteria": [
                {"criterion": name, "evidence": evidence}
                for item in top_level_result.get("passed_criteria", [])
                for name, _, evidence in [_parse_criterion(item)]
            ],
            "failed_criteria": [
                {"criterion": name, "reason": reason, "evidence": evidence}
                for item in top_level_result.get("failed_criteria", [])
                for name, reason, evidence in [_parse_criterion(item)]
            ],
            "reasoning": top_level_result.get("reasoning", error_message or ""),
        },
        "improvement_recommendations": all_recommendations,
        "platform_details": {
            "version_control": platform_data.vcs_type if platform_data else "",
            "cloud_platform": platform_data.cloud_type if platform_data else "",
            "assessment_timestamp": datetime.utcnow().isoformat() + "Z",
        },
        "level_wise_criteria": level_wise_criteria,
        "level_breakdown": level_breakdown,
        "platform": {
            "api_call_log": platform_data.api_call_log if platform_data else [],
        },
    }

    # --- Persist final state to DB (additional_info = full final_result, same as all sibling workflows) ---
    status = "FAILED" if error_message else "COMPLETED"
    if result_id:
        db = SessionLocal()
        try:
            AssessmentResultRepository.update_assessment_result(
                db=db,
                result_id=result_id,
                status=status,
                domain_score=final_score,
                reasoning=final_result["assessment_details"]["reasoning"],
                improvement_recommendations=all_recommendations,
                additional_info=final_result,
            )
        except Exception as exc:
            logger.error("Failed to update assessment record: %s", exc, exc_info=True)
        finally:
            db.close()

    logger.info("── format_result_node: result=%s ──", status)
    return {"final_result": final_result, "status": "completed"}
