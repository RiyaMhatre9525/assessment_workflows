# WORKFLOW_TEMPLATE_CONTEXT.md
# DevSecOps Assessment Backend — Workflow Creation Template Context
#
# PURPOSE: Use this file as context when creating a NEW workflow in a fresh chat.
# Provide this file + the new workflow name + its levels/criteria.
# The AI will generate all files following the exact same patterns used here.

---

## HOW TO USE THIS FILE IN A NEW CHAT

Paste this entire file as context, then say:

> "Using this context, create a new workflow called `<workflow_name>` with the
> following levels and criteria: [describe levels]"

The AI will generate:
- `workflows/<workflow_name>/__init__.py`
- `workflows/<workflow_name>/config.py`
- `workflows/<workflow_name>/nodes.py`
- `workflows/<workflow_name>/graph.py`
- `workflows/<workflow_name>/connectors/__init__.py`  *(if platform connectors needed)*
- `workflows/<workflow_name>/connectors/base.py`       *(if platform connectors needed)*
- `workflows/<workflow_name>/connectors/<platform>.py` *(one per platform)*
- `workflows/<workflow_name>/README.md`
- `api_routes_patch.py`                                *(shows what to add to routes.py)*

---

## PART 1 — PROJECT OVERVIEW

**What the project is:**
A FastAPI backend that runs DevSecOps security assessments using AI agents.
Requests hit an API, get routed to a workflow, which runs a LangGraph state
machine, and returns structured JSON.

**Tech stack:**
- Python 3.12
- FastAPI + Uvicorn (HTTP layer)
- LangChain + LangGraph (agent + state machine)
- OpenAI GPT-4o-mini (LLM, via LLMProvider singleton)
- httpx (async HTTP for platform API calls)
- pydantic-settings (config from .env)

**Folder structure:**
```
project_root/
├── main.py                        ← FastAPI app, middleware, startup
├── config/
│   └── settings.py                ← Settings(BaseSettings) + get_settings()
├── core/
│   ├── logger.py                  ← get_logger(name) factory
│   └── llm_provider.py            ← LLMProvider singleton → ChatOpenAI
├── workflows/
│   ├── base_workflow.py           ← BaseWorkflow (ABC)
│   ├── test_search/               ← Example existing workflow (do not modify)
│   └── <new_workflow>/            ← NEW workflow goes here
├── api/
│   ├── models.py                  ← WorkflowRequest, WorkflowResponse (Pydantic)
│   └── routes.py                  ← WORKFLOWS registry + FastAPI endpoints
└── requirements.txt
```

**Dependency flow (never reverse this):**
```
config/ ◀── core/ ◀── workflows/ ◀── api/ ◀── main.py
```

**API endpoints:**
```
GET  /health
GET  /api/workflows
POST /api/execute/{workflow_name}
     Body: {"input_data": { ...workflow-specific fields... }}
```

---

## PART 2 — CORE INFRASTRUCTURE (never modify these)

### core/logger.py

```python
# Usage in every file:
from core.logger import get_logger
logger = get_logger(__name__)

# Logging conventions:
logger.info("── node_name: START ──")
logger.info("── node_name: result=%s", value)
logger.error("Description: %s", exc, exc_info=True)
logger.warning("Non-critical issue: %s", detail)
```

### core/llm_provider.py

```python
# Always use the singleton — never instantiate ChatOpenAI directly:
from core.llm_provider import LLMProvider

llm = LLMProvider().get_llm()   # returns the shared ChatOpenAI instance
response = await llm.ainvoke([SystemMessage(...), HumanMessage(...)])
raw_text = response.content
```

### workflows/base_workflow.py

```python
class BaseWorkflow(ABC):
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
        self.graph = self.build_graph()    # called once at construction

    @abstractmethod
    def build_graph(self) -> Any:
        """Wire StateGraph, compile, return compiled graph."""

    @abstractmethod
    def initialize_state(self, input_data: dict) -> dict:
        """Validate input_data, return initial state dict."""

    @abstractmethod
    def extract_result(self, final_state: dict) -> dict:
        """Pull final_result from final_state, return it."""

    async def run(self, input_data: dict) -> dict:     # DO NOT override
        start_time = time.time()
        try:
            state = self.initialize_state(input_data)
            if self.graph is None:
                raise RuntimeError("Graph not compiled.")
            
            final_state = await self.graph.ainvoke(state)
            result = self.extract_result(final_state)
            
            elapsed = time.time() - start_time
            self.logger.info("Workflow '%s' completed in %.2fs", self.name, elapsed)
            return result
        except Exception as exc:
            self.logger.error("Workflow '%s' failed", self.name, exc_info=True)
            
            # Persist FAILED state to database if assessment_id is available
            assessment_id = None
            if 'state' in locals() and isinstance(state, dict):
                assessment_id = state.get("assessment_id")
            if not assessment_id and isinstance(input_data, dict):
                assessment_id = input_data.get("assessment_id")

            if assessment_id:
                try:
                    from core.database import SessionLocal
                    from core.repositories.assessment_result_repository import AssessmentResultRepository
                    db = SessionLocal()
                    try:
                        domain_name = getattr(self, "domain_name", "UNKNOWN")
                        AssessmentResultRepository.insert_assessment_result(
                            db=db,
                            assessment_id=assessment_id,
                            status="FAILED",
                            domain_name=domain_name,
                            domain_score=0.0,
                            reasoning=f"Workflow terminated due to error: {str(exc)}",
                            improvement_recommendations=[],
                            additional_info={"error": str(exc)}
                        )
                    finally:
                        db.close()
                except Exception as db_exc:
                    self.logger.error("Failed to save FAILED status to database: %s", db_exc)
            raise
```

### api/routes.py (WORKFLOWS registry & Async Invocation)

```python
from fastapi import APIRouter, HTTPException, BackgroundTasks
from api.models import WorkflowRequest, WorkflowResponse
from workflows.test_search.graph import TestSearchWorkflow
from workflows.build_domain.graph import PipelineMaturityWorkflow
# ← import new workflow here

WORKFLOWS: Dict[str, object] = {
    "test_search": TestSearchWorkflow(),
    "build_domain": PipelineMaturityWorkflow(),
    # ← register new workflow here: "workflow_key": MyWorkflow()
}

@router.post("/execute/{workflow_name}", response_model=WorkflowResponse)
async def execute_workflow(
    workflow_name: str,
    request: WorkflowRequest,
    background_tasks: BackgroundTasks
) -> WorkflowResponse:
    workflow = WORKFLOWS.get(workflow_name)
    if not workflow:
        raise HTTPException(status_code=404, detail="Workflow not found")

    try:
        # Pre-validate inputs synchronously
        workflow.initialize_state(request.input_data)
    except ValueError as ve:
        return WorkflowResponse(workflow=workflow_name, status="error", error=str(ve))

    # Run workflow asynchronously in the background
    background_tasks.add_task(workflow.run, request.input_data)
    
    return WorkflowResponse(
        workflow=workflow_name,
        status="in_progress",
        result=None,
    )
```

---

## PART 3 — DESIGN PATTERNS (always follow these)

### Pattern 1: Node signature
```python
# Nodes ONLY return keys they changed — LangGraph merges into state
async def my_node(state: dict) -> dict:
    data = state["some_key"]         # read
    result = await do_work(data)     # work
    return {"output_key": result, "status": "done"}   # write only changed keys
```

### Pattern 2: State TypedDict
```python
# total=False is REQUIRED so fields don't all need to exist upfront
class MyWorkflowState(TypedDict, total=False):
    field_set_at_start: str
    field_set_by_node1: str
    field_set_by_node2: dict
    status: str
    stop_flag: bool
    final_result: dict
    error_message: str
```

### Pattern 3: Fail-fast conditional edges
```python
def _should_stop(state: dict) -> str:
    return "format_result" if state.get("stop_flag") else "continue"

# In build_graph():
graph.add_conditional_edges(
    "level1",
    _should_stop,
    {"format_result": "format_result", "continue": "level2"},
)
```

### Pattern 4: LLM call in a node (async, JSON output)
```python
import json, re
from langchain_core.messages import HumanMessage, SystemMessage

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
```

### Pattern 5: Error state (node never crashes the graph)
```python
async def my_node(state: dict) -> dict:
    try:
        # ... work ...
        return {"result": data, "status": "done"}
    except Exception as exc:
        logger.error("my_node failed: %s", exc, exc_info=True)
        return {"status": "error", "error_message": str(exc), "stop_flag": True}
```

### Pattern 6: Platform connector (for workflows that query external APIs)
```python
class BasePlatformConnector(ABC):
    def __init__(self, credentials: dict) -> None:
        self.credentials = credentials
        self._api_call_log: list[str] = []

    def _log(self, message: str) -> None:
        self._api_call_log.append(message)

    @abstractmethod
    async def collect(self, repository: str) -> PlatformData: ...

    @abstractmethod
    async def health_check(self) -> bool: ...

# Connector registry pattern (in connectors/__init__.py):
CONNECTOR_REGISTRY: dict[str, type[BasePlatformConnector]] = {
    "github": GitHubConnector,
    "azure_devops": AzureDevOpsConnector,
}
# To add a new platform: add one entry here — no other files change.
```

### Pattern 7: LLM system prompt for level assessment (always JSON output)
```python
LEVEL_N_SYSTEM_PROMPT = """
You are a <domain> assessor for Level N: <Level Title>.

Criteria (ALL must pass to advance):
1. <criterion 1>
2. <criterion 2>
3. <criterion 3>

Scoring (<score_min>–<score_max>):
  - <score_min>:   <description of lowest score>
  - <mid_score>:  <description of partial pass>
  - <score_max>:   Full Level N pass — all criteria met

Respond ONLY with valid JSON:
{
  "level": N,
  "passed": <boolean>,
  "score": <float score_min–score_max>,
  "passed_criteria": [<strings>],
  "failed_criteria": [<strings>],
  "reasoning": "<concise explanation>",
  "recommendations": [
    {"gap": "<specific gap>", "action": "<concrete action>", "priority": "<high|medium|low>"}
  ]
}
"""
```

---

## PART 4 — THE BUILD DOMAIN WORKFLOW (reference implementation)

This is the complete workflow that was built. Use it as the exact structural
template for all new workflows.

### Workflow summary
- **Key:** `build_domain`
- **Class:** `PipelineMaturityWorkflow`
- **Purpose:** Assess build pipeline maturity across GitHub / Azure DevOps
- **Levels:** 5 progressive levels with fail-fast logic
- **Connectors:** GitHub, Azure DevOps (extensible)

### API call format
```json
POST /api/execute/build_domain
{
  "input_data": {
    "assessment_id": "33333333-3333-3333-3333-333333333333",
    "platform_type": "github",
    "repository": "myorg/myrepo",
    "branch": "main",
    "credentials": {
      "token": "<github-pat>"
    }
  }
}
```

### API response format (returned immediately for async processing)
```json
{
  "workflow": "build_domain",
  "status": "in_progress",
  "result": null,
  "error": null,
  "timestamp": "2026-06-17T21:22:05.123456"
}
```

### Database Persistence
Results are persisted to `assessment_result` table:
- **Successful Run (Status: `COMPLETED`)**:
  ```json
  {
    "maturity_level": 2,
    "score": 1.3,
    "score_range": "1.0–2.0",
    "assessment_details": {
      "passed_criteria": ["Image digests used"],
      "failed_criteria": ["No SBOM generation step found"],
      "reasoning": "The platform uses image digests for container images, but there is no enforcement of immutability..."
    },
    "improvement_recommendations": [
      {
        "gap": "Immutability enforcement for container images",
        "action": "Implement registry policies to prevent overwriting of tags",
        "priority": "high"
      }
    ],
    "level_breakdown": {
      "1": {"passed": true, "score": 1.0},
      "2": {"passed": false, "score": 1.3}
    }
  }
  ```
- **Error Run (Status: `FAILED`)**:
  Saves error message in `reasoning` and trace under `additional_info`.


### File structure
```
workflows/pipeline_maturity/
├── __init__.py          ← package docstring
├── README.md            ← API usage, levels table, connector guide
├── config.py            ← LEVEL_SCORE_RANGES, LEVEL_DESCRIPTIONS, LLM prompts
├── nodes.py             ← one async node per level + collect + format_result
├── graph.py             ← PipelineMaturityState TypedDict + PipelineMaturityWorkflow
└── connectors/
    ├── __init__.py      ← CONNECTOR_REGISTRY dict
    ├── base.py          ← BasePlatformConnector ABC + shared dataclasses
    ├── github.py        ← GitHubConnector
    └── azure_devops.py  ← AzureDevOpsConnector
```

### config.py structure
```python
# Scoring boundaries per level
LEVEL_SCORE_RANGES: dict[int, tuple[float, float]] = {
    1: (0.0, 1.0),
    2: (1.0, 2.0),
    3: (2.0, 3.0),
    4: (3.0, 4.0),
    5: (4.0, 5.0),
}

LEVEL_DESCRIPTIONS: dict[int, str] = {
    1: "Build Process Definition",
    2: "Artifact Pinning & SBOM",
    # ...
}

# One system prompt constant per level:
LEVEL1_SYSTEM_PROMPT = """...(see Pattern 7 above)..."""
LEVEL2_SYSTEM_PROMPT = """..."""
# etc.
```

### nodes.py structure
```python
# Node 0: always first — collect data from platform
async def collect_platform_data_node(state: dict) -> dict:
    # 1. Look up connector from CONNECTOR_REGISTRY using state["platform_type"]
    # 2. Run health_check() — return error state if fails
    # 3. Run connector.collect(repository) — return error state if fails
    # 4. Return: {"platform_data": pd, "status": "data_collected", "stop_assessment": False}

# Nodes 1–N: one per maturity level
async def level1_node(state: dict) -> dict:
    if state.get("stop_assessment"): return {}   # skip if already stopped
    # 1. Build platform summary string from state["platform_data"]
    # 2. Call _async_llm(LEVEL1_SYSTEM_PROMPT, summary)
    # 3. If passed: return {"level_results": ..., "current_level": 1, "stop_assessment": False}
    # 4. If failed: return {"level_results": ..., "current_level": 1, "final_score": score,
    #                        "stop_assessment": True, "status": "assessment_stopped_at_level_1"}

# Terminal node: always last
async def format_result_node(state: dict) -> dict:
    # Build final_result dict from level_results, current_level, final_score
    # Return: {"final_result": {...}, "status": "completed"}
```

### graph.py structure
```python
class PipelineMaturityState(TypedDict, total=False):
    # Inputs
    platform_type: str
    credentials: dict
    repository: str
    # Intermediate
    platform_data: Any
    level_results: dict
    current_level: int
    stop_assessment: bool
    final_score: float
    error_message: str
    # Output
    final_result: dict
    status: str

class PipelineMaturityWorkflow(BaseWorkflow):
    def __init__(self):
        super().__init__(name="Pipeline Maturity Assessment", description="...")

    def build_graph(self):
        graph = StateGraph(PipelineMaturityState)

        # Add nodes
        graph.add_node("collect_platform_data", collect_platform_data_node)
        graph.add_node("level1", level1_node)
        # ... more levels ...
        graph.add_node("format_result", format_result_node)

        # Entry point
        graph.set_entry_point("collect_platform_data")
        graph.add_edge("collect_platform_data", "level1")

        # Conditional edges (fail-fast)
        graph.add_conditional_edges("level1", _should_stop,
            {"format_result": "format_result", "continue": "level2"})
        # ... repeat for each level ...

        graph.add_edge("format_result", END)
        return graph.compile()

    def initialize_state(self, input_data: dict) -> dict:
        # Validate: platform_type, credentials, repository
        # Return initial state dict with stop_assessment=False, level_results={}

    def extract_result(self, final_state: dict) -> dict:
        return final_state.get("final_result", {"error": "Assessment did not complete"})
```

### Scoring convention
```
Level N score range: (N-1) to N
  e.g. Level 1: 0.0–1.0 | Level 2: 1.0–2.0 | Level 3: 2.0–3.0

Score semantics within a level:
  <level_min + 0.0>  → nothing detected / no criteria met
  <level_min + 0.3>  → exists but mostly missing
  <level_min + 0.5>  → partial pass (some criteria met)
  <level_min + 0.8>  → most criteria met, minor gaps
  <level_max>        → full pass, all criteria met
```

### Connector data classes (base.py)
```python
@dataclass
class PipelineInfo:
    name: str; path: str; raw_content: str = ""
    has_build_job: bool = False
    has_test_job: bool = False
    has_security_scan_job: bool = False

@dataclass
class ArtifactInfo:
    name: str; tag: str; digest: str = ""
    immutability_enforced: bool = False
    sbom_detected: bool = False; sbom_tool: str = ""

@dataclass
class CommitSigningInfo:
    total_commits_checked: int = 0
    signed_commits: int = 0; unsigned_commits: int = 0
    branch_protection_enforced: bool = False
    required_signed_commits_policy: bool = False

@dataclass
class ArtifactSigningInfo:
    signing_tool_detected: str = ""
    all_artifacts_signed: bool = False
    signature_verification_in_deployment: bool = False

@dataclass
class PlatformData:
    platform_type: str; repository: str
    pipelines: list[PipelineInfo] = field(default_factory=list)
    artifacts: list[ArtifactInfo] = field(default_factory=list)
    commit_signing: CommitSigningInfo = field(default_factory=CommitSigningInfo)
    artifact_signing: ArtifactSigningInfo = field(default_factory=ArtifactSigningInfo)
    raw_metadata: dict = field(default_factory=dict)
    api_call_log: list[str] = field(default_factory=list)
```

---

## PART 5 — RULES FOR THE AI GENERATING A NEW WORKFLOW

When generating a new workflow using this context, the AI MUST:

### Structural rules
1. **Mirror the build_domain file structure exactly** — same folder layout, same file names.
2. **One file per concern** — config.py for prompts/constants, nodes.py for node functions, graph.py for wiring.
3. **Never put nodes inside graph.py** — nodes.py is always separate.
4. **Never modify** `core/`, `config/`, `api/models.py`, or `workflows/base_workflow.py`.
5. **Only touch** `api/routes.py` via the `api_routes_patch.py` file showing what to add.

### Coding rules
6. **All nodes are async** — `async def node_name(state: dict) -> dict`.
7. **Return only changed keys** from nodes — never return the full state.
8. **`total=False` on every TypedDict** — no exceptions.
9. **Always use `LLMProvider().get_llm()`** — never instantiate `ChatOpenAI` directly.
10. **Log every node start** — `logger.info("── node_name: START ──")`.
11. **Every node has try/except** — failures set `stop_flag=True` and `error_message`, never crash.
12. **Never import from api/ inside workflows/** — keep the dependency flow clean.

### LLM prompt rules
13. **Every level has its own system prompt constant** in `config.py`.
14. **Every prompt ends with a strict JSON schema** the model must follow.
15. **Strip markdown fences** before `json.loads()`.
16. **Prompts include explicit scoring guidance** for every score band in the level's range.

### Connector rules (if the workflow queries external APIs)
17. **One connector per platform file** — never put two platforms in one file.
18. **All connectors inherit `BasePlatformConnector`** and implement `health_check()` + `collect()`.
19. **Log every API call** via `self._log(f"GET {url}")` before making it.
20. **CONNECTOR_REGISTRY in connectors/__init__.py** is the only place platform names are mapped.
21. **Adding a new platform = one new file + one new dict entry** — no other changes needed.

### Assessment flow rules
22. **Fail-fast** — `stop_assessment=True` at any level stops the graph immediately.
23. **Skipped nodes must check** `if state.get("stop_assessment"): return {}` at the top.
24. **format_result_node is always terminal** — it always runs regardless of stop point.
25. **Level 4 placeholder** — if Level 4 criteria are not yet defined, auto-pass with a note.

### Output rules
26. **All recommendations are aggregated** across every completed level in `format_result_node`.
27. **`level_breakdown` always included** in the final result.
28. **`platform.api_call_log` always included** in the final result for debugging.
29. **README.md always included** with: API usage, levels table, credentials reference, connector guide.

### Database & Persistence rules
30. **Ensure all workflow executions persist results to the database**:
    - The terminal node (`format_result_node`) must persist successful results with status `COMPLETED` using `AssessmentResultRepository.insert_assessment_result(...)`.
    - Catch failures/errors in `BaseWorkflow.run` and save a record with status `FAILED` in the database.
31. **UUID primary key generation**:
    - The database table has a primary key `id` of type `uuid` with NO default value.
    - Before calling the SQL insert statement in the repository, you must generate a new UUID4 string in Python (`str(uuid.uuid4())`) and pass it as the `id` value.

---

## PART 6 — COMMON MISTAKES TO AVOID

```python
# ❌ WRONG — total=False missing → crash on initialize_state
class MyState(TypedDict):
    result: dict   # doesn't exist yet!

# ✅ CORRECT
class MyState(TypedDict, total=False):
    result: dict

# ❌ WRONG — returns full state (overwrites all keys)
async def my_node(state: dict) -> dict:
    return state

# ✅ CORRECT — only changed keys
async def my_node(state: dict) -> dict:
    return {"result": data, "status": "done"}

# ❌ WRONG — creates a new LLM instance per request
llm = ChatOpenAI(model="gpt-4o-mini", api_key="...")

# ✅ CORRECT — reuses singleton
llm = LLMProvider().get_llm()

# ❌ WRONG — blocks the event loop
result = agent.invoke({"input": query})

# ✅ CORRECT — non-blocking
result = await agent.ainvoke({"input": query})

# ❌ WRONG — build_graph() returns None → RuntimeError
def build_graph(self):
    graph = StateGraph(MyState)
    graph.compile()   # compiled but not returned!

# ✅ CORRECT
def build_graph(self):
    graph = StateGraph(MyState)
    return graph.compile()

# ❌ WRONG — importing api/ from workflows/ (breaks dependency flow)
from api.models import WorkflowRequest  # inside a workflow file

# ✅ CORRECT — workflows never import from api/
```

---

## PART 7 — QUICK CHECKLIST BEFORE FINISHING A WORKFLOW

- [ ] `workflows/<name>/__init__.py` exists with package docstring
- [ ] `config.py` has `LEVEL_SCORE_RANGES`, `LEVEL_DESCRIPTIONS`, one prompt per level
- [ ] `nodes.py` has: collect node, one node per level, format_result node
- [ ] Every node checks `stop_assessment` at the top and returns `{}` if True
- [ ] `graph.py` has TypedDict with `total=False` and all expected keys
- [ ] `build_graph()` returns `graph.compile()`
- [ ] `initialize_state()` raises `ValueError` for missing required fields
- [ ] `extract_result()` has a fallback for missing `final_result`
- [ ] `connectors/__init__.py` has `CONNECTOR_REGISTRY` dict
- [ ] `connectors/base.py` has `BasePlatformConnector` ABC + dataclasses
- [ ] Each connector logs every API call via `self._log()`
- [ ] `README.md` exists with API usage + levels table + credential keys
- [ ] `api_routes_patch.py` shows the import + dict entry to add
- [ ] All Python files pass `ast.parse()` (no syntax errors)
- [ ] All async node calls use `await` (no blocking `.invoke()`)

---

*End of WORKFLOW_TEMPLATE_CONTEXT.md*
*Version: 1.0.0 | Created from: pipeline_maturity workflow implementation*
*Use this file in any new chat to generate a consistent, correctly-structured workflow.*
