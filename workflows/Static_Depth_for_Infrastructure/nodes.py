"""
Assessment nodes for the Static_Depth_for_Infrastructure workflow.
 
Node order:
    collect_platform_data_node
        -> level1_node   (Secrets Hygiene — real controls, LLM-assessed)
        -> level2_node   (Deployment, Runtime & Cloud Configuration Security)
        -> level3_node   (Malware & Image Freshness)
        -> level4_node   (Vulnerability Correlation & SCA)
        -> level5_node   (no controls defined — always passes if reached)
        -> format_result_node (always runs, regardless of stop point)
 
Reporting convention (per this workflow's spec — "Return the current
maturity level along with detailed findings"): `maturity_level` is the level
the workflow was evaluating when it stopped, whether that level itself
passed or failed. This matches Development_and_Source_Control and
Dynamic_Depth_for_Applications, and differs from Static_Depth_for_Applications
(which reports the highest FULLY PASSED level instead) — each workflow's own
spec dictates its convention.
 
Evidence grounding: the LLM is instructed (see config.py's schema suffix) to
only mark a criterion PASSED when it can cite matched evidence. As a second,
code-enforced safeguard, `_apply_evidence_floor` downgrades any
LLM-claimed PASS to FAILED if `detected_signals` (source control + cloud)
has genuinely no entry at all for that criterion — this prevents the model
from hallucinating a pass with zero supporting evidence, independent of how
well it follows the prompt instruction.
"""
 
from __future__ import annotations
 
import json
import re
 
from langchain_core.messages import HumanMessage, SystemMessage
 
from core.llm_provider import LLMProvider
from core.logger import get_logger
from workflows.Static_Depth_for_Infrastructure.config import (
    LEVEL1_SYSTEM_PROMPT,
    LEVEL2_SYSTEM_PROMPT,
    LEVEL3_SYSTEM_PROMPT,
    LEVEL4_SYSTEM_PROMPT,
    LEVEL_CRITERIA_NAMES,
    LEVEL_DESCRIPTIONS,
    LEVEL_SCORE_RANGES,
)
from workflows.Static_Depth_for_Infrastructure.connectors import (
    CLOUD_CONNECTOR_REGISTRY,
    SOURCE_CONTROL_CONNECTOR_REGISTRY,
)
from workflows.Static_Depth_for_Infrastructure.connectors.base import InfrastructureDepthPlatformData
 
logger = get_logger(__name__)
 
DOMAIN_NAME = "Static_Depth_for_Infrastructure"
ALL_LEVELS = [1, 2, 3, 4, 5]
 
 
# ---------------------------------------------------------------------------
# Shared helpers
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
 
 
def _parse_criterion(item) -> tuple[str, str]:
    if isinstance(item, dict):
        return item.get("name", ""), item.get("reason", "")
    return item, ""
 
 
def _combined_evidence_keys(platform_data: InfrastructureDepthPlatformData) -> set[str]:
    keys = {k for k, v in platform_data.source_control.detected_signals.items() if v}
    if platform_data.cloud:
        keys |= {k for k, v in platform_data.cloud.detected_signals.items() if v}
    return keys
 
 
def _apply_evidence_floor(level: int, llm_result: dict, evidence_keys: set[str]) -> dict:
    """Downgrade any LLM-claimed PASS for a criterion with zero detected
    evidence to FAILED. This is a hard, code-enforced floor — independent of
    whether the LLM followed the prompt's grounding instruction."""
    if "error" in llm_result:
        return llm_result
 
    passed_criteria = llm_result.get("passed_criteria", [])
    failed_criteria = list(llm_result.get("failed_criteria", []))
    kept_passed = []
 
    for item in passed_criteria:
        name, reason = _parse_criterion(item)
        if name in evidence_keys:
            kept_passed.append(item)
        else:
            logger.warning(
                "level%d: downgrading ungrounded PASS for '%s' (no detected_signals evidence) to FAILED",
                level, name,
            )
            failed_criteria.append({
                "name": name,
                "reason": "No supporting evidence detected in collected pipeline/repository/cloud data.",
            })
 
    llm_result = dict(llm_result)
    llm_result["passed_criteria"] = kept_passed
    llm_result["failed_criteria"] = failed_criteria
    llm_result["passed"] = len(failed_criteria) == 0 and len(kept_passed) > 0
    return llm_result
 
 
def _score_from_counts(level: int, passed_count: int, total_count: int) -> float:
    level_min, level_max = LEVEL_SCORE_RANGES[level]
    if total_count <= 0:
        return level_min
    return round(level_min + (passed_count / total_count) * (level_max - level_min), 4)
 
 
def _finalize_level_result(level: int, llm_result: dict) -> dict:
    """Normalize an (evidence-floored) LLM result into a level_results entry
    with an exact, deterministic score computed from passed/failed counts."""
    if "error" in llm_result:
        return {
            "level": level,
            "passed": False,
            "score": LEVEL_SCORE_RANGES[level][0],
            "passed_criteria": [],
            "failed_criteria": [{"name": name, "reason": "Assessment error."} for name in LEVEL_CRITERIA_NAMES[level]],
            "reasoning": f"LLM assessment failed: {llm_result['error']}",
            "evidence": [],
            "findings": [],
            "security_risks": [],
            "recommendations": [],
        }
 
    passed_criteria = llm_result.get("passed_criteria", [])
    failed_criteria = llm_result.get("failed_criteria", [])
    total = len(passed_criteria) + len(failed_criteria)
    if total == 0:
        total = len(LEVEL_CRITERIA_NAMES.get(level, [])) or 1
 
    score = _score_from_counts(level, len(passed_criteria), total)
    passed = len(failed_criteria) == 0 and len(passed_criteria) > 0
 
    return {
        "level": level,
        "passed": passed,
        "score": score,
        "passed_criteria": passed_criteria,
        "failed_criteria": failed_criteria,
        "reasoning": llm_result.get("reasoning", ""),
        "evidence": llm_result.get("evidence", []),
        "findings": llm_result.get("findings", []),
        "security_risks": llm_result.get("security_risks", []),
        "recommendations": llm_result.get("recommendations", []),
    }
 
 
def _platform_summary(platform_data: InfrastructureDepthPlatformData) -> str:
    sc = platform_data.source_control
    lines = [
        f"Source control platform: {sc.platform_type}",
        f"Repository: {sc.repository}",
        f"Pipeline definitions collected: {len(sc.pipeline_definitions)}",
        f"Repository files indexed: {len(sc.repository_files)}",
        "Detected signals from source control (criterion -> matched indicators):",
    ]
    for criterion, matches in sc.detected_signals.items():
        lines.append(f"  - {criterion}: {matches}")
    if not sc.detected_signals:
        lines.append("  (none detected)")
 
    if platform_data.cloud:
        lines.append(f"Cloud platform: {platform_data.cloud.platform_type}")
        lines.append("Detected signals from cloud (criterion -> matched indicators):")
        for criterion, matches in platform_data.cloud.detected_signals.items():
            lines.append(f"  - {criterion}: {matches}")
        if not platform_data.cloud.detected_signals:
            lines.append("  (none detected)")
    else:
        lines.append("Cloud platform: NOT PROVIDED — no cloud-level evidence available.")
 
    relevant_files = [
        f for f in sc.repository_files
        if any(kw in f.lower() for kw in [
            ".tf", ".bicep", "arm-template", "helm", "k8s", "kubernetes",
            "dockerfile", "checkov", "tfsec",
        ])
    ][:30]
    if relevant_files:
        lines.append(f"Relevant IaC/deployment files found: {relevant_files}")
 
    # ---------------- ADD THIS BLOCK ----------------
    lines.append("\nDetailed detected evidence:")
 
    for criterion, matches in sc.detected_signals.items():
        lines.append(f"{criterion}")
        for match in matches:
            lines.append(f"  - {match}")
 
    if platform_data.cloud:
        lines.append("\nCloud evidence:")
        for criterion, matches in platform_data.cloud.detected_signals.items():
            lines.append(f"{criterion}")
            for match in matches:
                lines.append(f"  - {match}")
    # -------------- END OF BLOCK --------------------
 
    for pipeline in sc.pipeline_definitions[:5]:
        snippet = pipeline.raw_content[:5000]
        lines.append(f"\n--- Pipeline: {pipeline.name} ({pipeline.path}) ---\n{snippet}")
 
    return "\n".join(lines)
 
 
# ---------------------------------------------------------------------------
# Node 0 — collect evidence from source control + cloud connectors
# ---------------------------------------------------------------------------
async def collect_platform_data_node(state: dict) -> dict:
    logger.info("── collect_platform_data_node: START ──")
 
    assessment_id = state.get("assessment_id")
    result_id = None
    try:
        from core.database import SessionLocal
        from core.repositories.assessment_result_repository import AssessmentResultRepository
 
        db = SessionLocal()
        try:
            result_id = AssessmentResultRepository.insert_assessment_result_returning_id(
                db=db,
                assessment_id=assessment_id,
                status="IN_PROGRESS",
                domain_name=DOMAIN_NAME,
            )
        finally:
            db.close()
    except Exception as exc:
        logger.error("Failed to insert IN_PROGRESS assessment record: %s", exc)
 
    source_control_platform = state.get("source_control_platform")
    cloud_platform = state.get("cloud_platform")
    credentials = state.get("credentials", {})
    repository = state.get("repository", "")
 
    sc_connector_cls = SOURCE_CONTROL_CONNECTOR_REGISTRY.get(source_control_platform)
    if sc_connector_cls is None:
        return {
            "status": "error",
            "error_message": f"Unsupported source_control platform: {source_control_platform}",
            "stop_assessment": True,
            "result_id": result_id,
        }
 
    sc_connector = sc_connector_cls(credentials)
    healthy = await sc_connector.health_check()
    if not healthy:
        return {
            "status": "error",
            "error_message": f"Health check failed for source control platform: {source_control_platform}",
            "stop_assessment": True,
            "result_id": result_id,
        }
 
    try:
        source_control_data = await sc_connector.collect(repository)
    except Exception as exc:
        logger.error("collect_platform_data_node: source control collection failed: %s", exc, exc_info=True)
        return {
            "status": "error",
            "error_message": f"Source control data collection failed: {exc}",
            "stop_assessment": True,
            "result_id": result_id,
        }
 
    cloud_data = None
    if cloud_platform:
        cloud_connector_cls = CLOUD_CONNECTOR_REGISTRY.get(cloud_platform)
        if cloud_connector_cls is not None:
            try:
                cloud_connector = cloud_connector_cls(credentials)
                if await cloud_connector.health_check():
                    cloud_data = await cloud_connector.collect(credentials.get("subscription_id", ""))
                else:
                    logger.warning("Cloud health_check failed for platform: %s", cloud_platform)
            except Exception as exc:
                logger.warning("Cloud data collection skipped due to error: %s", exc)
    else:
        logger.warning(
            "No cloud_platform supplied — Level 2/3/4 criteria that depend on cloud "
            "evidence (cluster, cloud config, virtualization, image registry) will "
            "likely fail the evidence floor."
        )
 
    platform_data = InfrastructureDepthPlatformData(source_control=source_control_data, cloud=cloud_data)
 
    logger.info("── collect_platform_data_node: result=collected ──")
    return {
        "platform_data": platform_data,
        "status": "data_collected",
        "stop_assessment": False,
        "result_id": result_id,
    }
 
 
def _should_stop(state: dict) -> str:
    return "format_result" if state.get("stop_assessment") else "continue"
 
 
def _make_level_node(level: int, system_prompt: str):
    async def _node(state: dict) -> dict:
        logger.info("── level%d_node: START ──", level)
        if state.get("stop_assessment"):
            return {}
 
        try:
            platform_data = state["platform_data"]
 
            print("========== DETECTED SIGNALS ==========")
            print(platform_data)
 
            summary = _platform_summary(platform_data)
            llm_result = await _call_llm_json(system_prompt, summary)
 
            evidence_keys = _combined_evidence_keys(platform_data)
            llm_result = _apply_evidence_floor(level, llm_result, evidence_keys)
 
            print("\n========== LLM RESULT ==========")
            print(llm_result)
            print("================================")
 
            result = _finalize_level_result(level, llm_result)
 
            level_results = dict(state.get("level_results", {}))
            level_results[level] = result
 
            if result["passed"]:
                logger.info("── level%d_node: result=passed score=%.2f ──", level, result["score"])
                return {"level_results": level_results, "current_level": level, "stop_assessment": False}
 
            logger.info("── level%d_node: result=failed score=%.2f ──", level, result["score"])
            return {
                "level_results": level_results,
                "current_level": level,
                "stop_assessment": True,
                "status": f"assessment_stopped_at_level_{level}",
            }
        except Exception as exc:
            logger.error("level%d_node failed: %s", level, exc, exc_info=True)
            return {"status": "error", "error_message": str(exc), "stop_assessment": True}
 
    _node.__name__ = f"level{level}_node"
    return _node
 
 
level1_node = _make_level_node(1, LEVEL1_SYSTEM_PROMPT)
level2_node = _make_level_node(2, LEVEL2_SYSTEM_PROMPT)
level3_node = _make_level_node(3, LEVEL3_SYSTEM_PROMPT)
level4_node = _make_level_node(4, LEVEL4_SYSTEM_PROMPT)
 
 
# ---------------------------------------------------------------------------
# Node 5 — no controls defined, always passes once reached
# ---------------------------------------------------------------------------
async def level5_node(state: dict) -> dict:
    logger.info("── level5_node: START ──")
    if state.get("stop_assessment"):
        return {}
 
    level_min, level_max = LEVEL_SCORE_RANGES[5]
    level_results = dict(state.get("level_results", {}))
    level_results[5] = {
        "level": 5,
        "passed": True,
        "score": level_max,
        "passed_criteria": [],
        "failed_criteria": [],
        "reasoning": "No controls are currently defined for Level 5 — automatically achieved once Levels 1-4 fully pass.",
        "evidence": [],
        "findings": [],
        "security_risks": [],
        "recommendations": [],
    }
    logger.info("── level5_node: result=passed (no controls defined) ──")
    return {"level_results": level_results, "current_level": 5, "stop_assessment": False, "status": "assessment_completed"}
 
 
# ---------------------------------------------------------------------------
# Terminal node — always runs, builds the final structured response
# ---------------------------------------------------------------------------
def _build_level_wise_results(level_results: dict) -> list[dict]:
    failed_at_level = None
    for lvl in ALL_LEVELS:
        if lvl in level_results and not level_results[lvl].get("passed", True):
            failed_at_level = lvl
            break
 
    level_wise = []
    for lvl in ALL_LEVELS:
        lvl_name = LEVEL_DESCRIPTIONS.get(lvl, f"Level {lvl}")
        if lvl in level_results:
            res = level_results[lvl]
            node_results = []
            for item in res.get("passed_criteria", []):
                name, reason = _parse_criterion(item)
                node_results.append({"name": name, "status": "PASSED", "reason": reason})
            for item in res.get("failed_criteria", []):
                name, reason = _parse_criterion(item)
                node_results.append({"name": name, "status": "FAILED", "reason": reason})
            level_wise.append({
                "level": lvl, "level_name": lvl_name,
                "status": "PASSED" if res.get("passed") else "FAILED",
                "checked": True, "score": res.get("score"),
                "reasoning": res.get("reasoning", ""), "node_results": node_results,
            })
        else:
            if failed_at_level:
                failed_name = LEVEL_DESCRIPTIONS.get(failed_at_level, f"Level {failed_at_level}")
                skip_reason = (f"Level {failed_at_level} ({failed_name}) did not pass — "
                               f"assessment halted before reaching this level.")
            else:
                skip_reason = "Assessment did not reach this level."
            canonical = LEVEL_CRITERIA_NAMES.get(lvl, [])
            level_wise.append({
                "level": lvl, "level_name": lvl_name,
                "status": "NOT_CHECKED", "checked": False,
                "score": None, "reasoning": None,
                "node_results": [{"name": c, "status": "NOT_CHECKED", "reason": skip_reason} for c in canonical],
            })
    return level_wise
 
 
async def format_result_node(state: dict) -> dict:
    logger.info("── format_result_node: START ──")
 
    level_results: dict[int, dict] = state.get("level_results", {})
    current_level = state.get("current_level", 0)
    error_message = state.get("error_message")
    result_id = state.get("result_id")
 
    if error_message:
        final_result = {
            "workflow": DOMAIN_NAME,
            "maturity_level": current_level,
            "score": 0.0,
            "max_score": 5.0,
            "status": "ERROR",
            "level_wise_results": [],
            "node_wise_results": [],
            "passed_checks": [],
            "failed_checks": [],
            "evidence_collected": [],
            "findings": [],
            "reasoning": f"Assessment could not be completed: {error_message}",
            "missing_controls": [],
            "security_risks": [],
            "recommendations": [],
            "next_maturity_level": None,
            "summary": f"Assessment could not be completed: {error_message}",
            "error": error_message,
        }
        _persist(result_id, final_result, failed=True)
        return {"final_result": final_result, "status": "error"}
 
    final_result_level = current_level if current_level else 0
    result_at_level = level_results.get(final_result_level, {})
    score = result_at_level.get("score", LEVEL_SCORE_RANGES.get(final_result_level, (0.0, 0.0))[0] if final_result_level else 0.0)
    overall_status = "PASS" if result_at_level.get("passed") else "FAIL"
 
    node_wise_results: list[dict] = []
    passed_checks: list[str] = []
    failed_checks: list[str] = []
    evidence_collected: list[str] = []
    findings: list[str] = []
    missing_controls: list[str] = []
    security_risks: list[str] = []
    recommendations: list[dict] = []
 
    for lvl in ALL_LEVELS:
        res = level_results.get(lvl)
        if not res:
            continue
        for item in res.get("passed_criteria", []):
            name, why = _parse_criterion(item)
            passed_checks.append(f"Level {lvl}: {name}")
            node_wise_results.append({"level": lvl, "node": name, "status": "PASSED", "reason": why})
        for item in res.get("failed_criteria", []):
            name, why = _parse_criterion(item)
            failed_checks.append(f"Level {lvl}: {name}")
            missing_controls.append(f"Level {lvl}: {name} — {why}")
            node_wise_results.append({"level": lvl, "node": name, "status": "FAILED", "reason": why})
        evidence_collected.extend(res.get("evidence", []))
        findings.extend(res.get("findings", []))
        security_risks.extend(res.get("security_risks", []))
        for rec in res.get("recommendations", []):
            if isinstance(rec, dict):
                recommendations.append(rec)
            elif isinstance(rec, str):
                recommendations.append({"gap": "", "action": rec, "priority": "medium", "suggested_tools": []})
 
    next_maturity_level = final_result_level + 1 if final_result_level < 5 else None
 
    if final_result_level >= 5:
        summary = "All maturity levels were fully satisfied — maximum static infrastructure security maturity achieved."
    elif overall_status == "PASS":
        summary = f"Level {final_result_level} ({LEVEL_DESCRIPTIONS.get(final_result_level, '')}) was fully achieved."
    else:
        summary = (
            f"Assessment stopped at Level {final_result_level} "
            f"({LEVEL_DESCRIPTIONS.get(final_result_level, '')}) — "
            f"{len(result_at_level.get('failed_criteria', []))} control(s) failed. "
            f"Maturity Level = {final_result_level}."
        )
 
    final_result = {
        "workflow": DOMAIN_NAME,
        "maturity_level": final_result_level,
        "score": score,
        "max_score": 5.0,
        "status": overall_status,
        "level_wise_results": _build_level_wise_results(level_results),
        "node_wise_results": node_wise_results,
        "passed_checks": passed_checks,
        "failed_checks": failed_checks,
        "evidence_collected": evidence_collected,
        "findings": findings,
        "reasoning": result_at_level.get("reasoning", ""),
        "missing_controls": missing_controls,
        "security_risks": security_risks,
        "recommendations": recommendations,
        "next_maturity_level": next_maturity_level,
        "summary": summary,
    }
 
    _persist(result_id, final_result, failed=False)
 
    logger.info("── format_result_node: result=maturity_level=%s score=%.2f ──", final_result_level, score)
    return {"final_result": final_result, "status": "completed"}
 
 
def _persist(result_id, final_result: dict, failed: bool) -> None:
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
                status="FAILED" if failed else "COMPLETED",
                domain_score=final_result.get("score", 0.0),
                reasoning=final_result.get("summary", final_result.get("error", "")),
                improvement_recommendations=final_result.get("recommendations", []),
                additional_info=final_result,
            )
        finally:
            db.close()
    except Exception as exc:
        logger.error("Failed to persist assessment result: %s", exc)