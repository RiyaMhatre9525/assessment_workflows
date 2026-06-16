# PROJECT_CONTEXT.md — DevSecOps Assessment Backend

> **Audience:** Developers, AI models, and contributors who are **new** to
> this codebase.  Read this before writing any code.

---

## Table of Contents

- [Project Overview](#project-overview)
- [Architecture Overview](#architecture-overview)
- [Core Concepts](#core-concepts)
- [Design Patterns Used](#design-patterns-used)
- [Code Organisation](#code-organisation)
- [State Flow Diagram](#state-flow-diagram)
- [Key Files and Responsibilities](#key-files-and-responsibilities)
- [Configuration Management](#configuration-management)
- [Logging Strategy](#logging-strategy)
- [Error Handling](#error-handling)
- [Extending the Project](#extending-the-project)
- [Before You Code Checklist](#before-you-code-checklist)
- [Common Tasks](#common-tasks)
- [Common Mistakes](#common-mistakes)
- [Testing Guidelines](#testing-guidelines)
- [Deployment Considerations](#deployment-considerations)
- [Troubleshooting](#troubleshooting)
- [Future Enhancements](#future-enhancements)
- [Glossary](#glossary)
- [Quick Reference](#quick-reference)
- [Version History](#version-history)

---

## Project Overview

### What it does

This project is a **backend API server** that runs DevSecOps security
assessments using AI agents.  When a user sends a query (e.g. "Check for
OWASP Top-10 vulnerabilities in our React app"), the system:

1. Routes the request to the correct **workflow**.
2. The workflow's **LangGraph state machine** orchestrates a series of steps.
3. Each step may invoke an **LLM-powered agent** that uses **tools** to gather
   and analyse information.
4. The final assessment is returned as structured JSON.

### Who uses it

- **Security engineers** — run automated assessments via API calls.
- **CI/CD pipelines** — trigger security checks as a pipeline stage.
- **Dashboards / UIs** — display assessment results to stakeholders.
- **Other AI agents** — chain this backend into larger multi-agent systems.

### Why it exists

Manual security assessments are slow, inconsistent, and don't scale.  This
backend automates the research and analysis phase using LLM agents, producing
structured, repeatable results in seconds instead of hours.

---

## Architecture Overview

### High-Level System Design

```
                     ┌─────────────────────┐
                     │    HTTP Client       │
                     │ (curl / UI / CI/CD)  │
                     └─────────┬───────────┘
                               │  JSON over HTTP
                               ▼
┌──────────────────────────────────────────────────────────────┐
│                     FastAPI Application                       │
│                                                              │
│  ┌──────────┐    ┌───────────────────────┐    ┌───────────┐ │
│  │ main.py  │───▶│  api/routes.py        │───▶│ api/      │ │
│  │ (ASGI)   │    │  (WORKFLOWS registry) │    │ models.py │ │
│  └──────────┘    └───────────┬───────────┘    └───────────┘ │
│                              │                               │
│                    ┌─────────▼─────────┐                     │
│                    │ BaseWorkflow.run() │                     │
│                    │  1. init_state()   │                     │
│                    │  2. graph.ainvoke()│                     │
│                    │  3. extract_result()│                    │
│                    └─────────┬─────────┘                     │
│                              │                               │
│              ┌───────────────┼───────────────┐               │
│              │               │               │               │
│        ┌─────▼──────┐  ┌────▼─────┐  ┌──────▼──────┐       │
│        │  graph.py  │  │ nodes.py │  │  agents.py  │       │
│        │ (StateGraph)│  │ (funcs)  │  │ (ReAct loop)│       │
│        └────────────┘  └──────────┘  └──────┬──────┘       │
│                                             │               │
│                                    ┌────────▼────────┐      │
│                                    │  config.py      │      │
│                                    │  (prompts+tools)│      │
│                                    └─────────────────┘      │
│                                                              │
│  ┌─────────────────────┐  ┌────────────────────────┐        │
│  │  core/llm_provider  │  │  config/settings.py    │        │
│  │  (Singleton LLM)    │  │  (env vars + .env)     │        │
│  └────────┬────────────┘  └────────────────────────┘        │
│           │                                                  │
└───────────┼──────────────────────────────────────────────────┘
            │
     ┌──────▼──────┐
     │  OpenAI API │
     └─────────────┘
```

### Component Interaction Flow

```
Client Request
    │
    ▼
routes.py: look up WORKFLOWS[name]
    │
    ▼
BaseWorkflow.run(input_data)
    │
    ├──▶ initialize_state(input_data)  →  state = {query: "...", status: "init"}
    │
    ├──▶ graph.ainvoke(state)
    │       │
    │       ├──▶ search_node(state)  →  calls agent  →  calls tools  →  updates state
    │       │
    │       └──▶ process_node(state)  →  formats result  →  updates state
    │
    └──▶ extract_result(final_state)  →  return result dict
```

### Data Flow

Request JSON → Pydantic validation → `input_data` dict → `initialize_state()`
→ State TypedDict → Node 1 transforms → Node 2 transforms → `extract_result()`
→ Response dict → Pydantic serialisation → Response JSON.

---

## Core Concepts

### Workflows

A **workflow** is a self-contained assessment pipeline.  It has:

- **State schema** — a `TypedDict` defining what data flows through the pipeline.
- **Nodes** — async functions that transform the state.
- **Graph** — a `StateGraph` that defines execution order.
- **Lifecycle** — managed by `BaseWorkflow.run()`:
  1. `initialize_state()` — validate input, create initial state.
  2. `graph.ainvoke()` — run the state machine.
  3. `extract_result()` — format the final state for the API response.

Each workflow lives in its own package under `workflows/` and inherits from
`BaseWorkflow`.

**Lifecycle diagram:**

```
┌────────────────────┐
│ initialize_state() │  ← Validates input, creates state dict
└────────┬───────────┘
         │
         ▼
┌────────────────────┐
│  graph.ainvoke()   │  ← Runs nodes in order: search → process → END
│  ┌──────────────┐  │
│  │ search_node  │──┼──▶ Calls LLM agent → tool calls → observation
│  └──────┬───────┘  │
│         │          │
│  ┌──────▼───────┐  │
│  │ process_node │──┼──▶ Formats raw results into structured dict
│  └──────────────┘  │
└────────┬───────────┘
         │
         ▼
┌────────────────────┐
│  extract_result()  │  ← Pulls final_result from state, returns it
└────────────────────┘
```

### Agents

A LangChain **agent** is an LLM + tools + a reasoning loop.

**How the ReAct loop works:**

```
Input: "Find OWASP vulnerabilities"
  │
  ▼
Thought: "I should search for OWASP vulnerabilities"
  │
  ▼
Action: search_information("OWASP vulnerabilities")
  │
  ▼
Observation: "1. Broken Access Control... 2. Injection..."
  │
  ▼
Thought: "I have enough information to answer"
  │
  ▼
Final Answer: "Based on my research..."
```

The agent repeats the Thought → Action → Observation cycle until it has
enough information, or `max_iterations` is reached.

**Key components:**

| Component          | Purpose                                    | File               |
|--------------------|--------------------------------------------|---------------------|
| `ChatOpenAI`       | The LLM that does reasoning                | `llm_provider.py`   |
| `@tool` functions  | Actions the agent can take                  | `config.py`         |
| `ChatPromptTemplate`| System prompt + input + scratchpad        | `agents.py`         |
| `AgentExecutor`    | Manages the ReAct loop                     | `agents.py`         |

### Nodes

A **node** is an async function with the signature:

```python
async def my_node(state: dict) -> dict:
    # Read from state
    input_val = state["some_key"]

    # Do work
    result = await some_operation(input_val)

    # Return state UPDATES (not the full state)
    return {"output_key": result, "status": "done"}
```

LangGraph **merges** the returned dict into the existing state.  You only need
to return the keys that changed.

### State Management

State is a `TypedDict` — a regular Python dict with type annotations:

```python
class SearchWorkflowState(TypedDict, total=False):
    query: str              # Set by initialize_state
    search_results: str     # Set by search_node
    final_result: dict      # Set by process_node
    status: str             # Updated by every node
```

**Why `total=False`?**  Because not all keys exist at every stage.  The
initial state only has `query` and `status`; `search_results` is added later.

**State transformation example:**

```
After initialize_state():
  {query: "OWASP", status: "initialized"}

After search_node():
  {query: "OWASP", search_results: "1. Broken...", status: "search_completed"}

After process_node():
  {query: "OWASP", search_results: "1. Broken...",
   final_result: {query: "OWASP", assessment: "...", ...},
   status: "completed"}
```

### LLM Provider

The `LLMProvider` uses the **Singleton pattern** to ensure only one
`ChatOpenAI` instance exists across the entire application.

**Why Singleton?**

1. **Connection reuse** — shares HTTP sessions across requests.
2. **Consistency** — guarantees all agents use the same model/settings.
3. **Key isolation** — API key is configured in exactly one place.

```python
# Both of these return the SAME object:
llm1 = LLMProvider().get_llm()
llm2 = LLMProvider().get_llm()
assert llm1 is llm2  # True
```

---

## Design Patterns Used

### 1. Singleton Pattern — `LLMProvider`

```python
class LLMProvider:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._initialise_llm(cls._instance)
        return cls._instance
```

**When to use:** Shared resources that are expensive to create (DB connections,
HTTP clients, LLM instances).

### 2. Factory Pattern — Agent Creation

```python
def create_search_agent() -> AgentExecutor:
    llm = LLMProvider().get_llm()
    prompt = ChatPromptTemplate.from_messages([...])
    agent = create_openai_functions_agent(llm, tools, prompt)
    return AgentExecutor(agent=agent, tools=tools)
```

**When to use:** Complex object construction with many dependencies.

### 3. Abstract Base Class — `BaseWorkflow`

```python
class BaseWorkflow(ABC):
    @abstractmethod
    def build_graph(self) -> Any: ...

    @abstractmethod
    def initialize_state(self, input_data) -> dict: ...

    @abstractmethod
    def extract_result(self, final_state) -> dict: ...

    async def run(self, input_data):  # Template Method — do NOT override
        state = self.initialize_state(input_data)
        final = await self.graph.ainvoke(state)
        return self.extract_result(final)
```

**When to use:** Enforcing a common interface while allowing internal variation.

### 4. Registry Pattern — `WORKFLOWS` dict

```python
WORKFLOWS = {
    "test_search": TestSearchWorkflow(),
    "my_workflow": MyWorkflow(),
}
```

**When to use:** Dynamic dispatch by name without `if/elif` chains.

### 5. Dependency Injection — Configuration

```python
settings = get_settings()  # reads from .env / environment
llm = ChatOpenAI(model=settings.OPENAI_MODEL, ...)
```

**When to use:** Decoupling code from environment-specific values.

---

## Code Organisation

### Why each folder exists

| Folder       | Responsibility                          | Depends on          |
|--------------|-----------------------------------------|---------------------|
| `config/`    | Environment-driven settings             | (none)              |
| `core/`      | Shared infrastructure (logging, LLM)    | `config/`           |
| `workflows/` | Business logic (assessments)            | `core/`, `config/`  |
| `api/`       | HTTP interface                          | `workflows/`        |

### Import structure (dependency flow)

```
config/ ◀── core/ ◀── workflows/ ◀── api/ ◀── main.py
(no deps)    (config)   (core,config)  (workflows)  (api,config,core)
```

**Rule:** Dependencies flow **left to right**.  `config` never imports from
`core`; `core` never imports from `workflows`.  This prevents circular imports
and keeps the dependency graph clean.

### How modules communicate

Modules communicate through **function calls** and **shared types**:

- `api/routes.py` calls `workflow.run(input_data)` — passes a plain dict.
- `BaseWorkflow.run()` calls `self.graph.ainvoke(state)` — passes a TypedDict.
- Nodes return state-update dicts — LangGraph merges them.
- All modules access the LLM via `LLMProvider().get_llm()`.

There are **no global mutable variables**, **no message queues**, and **no
pub/sub** within the application.  Communication is synchronous (within
coroutines) and explicit.

---

## State Flow Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                        STATE FLOW                                │
│                                                                  │
│  API Request                                                     │
│  {"input_data": {"query": "OWASP Top-10"}}                      │
│        │                                                         │
│        ▼                                                         │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │ initialize_state(input_data)                              │    │
│  │   → Validates "query" field                               │    │
│  │   → Returns: {query: "OWASP Top-10", status: "init"}     │    │
│  └──────────────────────────────┬───────────────────────────┘    │
│                                 │                                │
│                                 ▼                                │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │ search_node(state)                                        │    │
│  │   → Reads: state["query"]                                 │    │
│  │   → Invokes: agent.ainvoke({"input": query})              │    │
│  │   → Agent calls: search_information(query)                │    │
│  │   → Returns: {search_results: "...", status: "done"}      │    │
│  └──────────────────────────────┬───────────────────────────┘    │
│                                 │                                │
│                                 ▼                                │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │ process_node(state)                                       │    │
│  │   → Reads: state["query"], state["search_results"]        │    │
│  │   → Builds: structured assessment dict                    │    │
│  │   → Returns: {final_result: {...}, status: "completed"}   │    │
│  └──────────────────────────────┬───────────────────────────┘    │
│                                 │                                │
│                                 ▼                                │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │ extract_result(final_state)                               │    │
│  │   → Reads: final_state["final_result"]                    │    │
│  │   → Returns: the assessment dict                          │    │
│  └──────────────────────────────┬───────────────────────────┘    │
│                                 │                                │
│                                 ▼                                │
│  API Response                                                    │
│  {"workflow": "test_search", "status": "success",                │
│   "result": {...}, "timestamp": "..."}                           │
└─────────────────────────────────────────────────────────────────┘
```

---

## Key Files and Responsibilities

| File                              | Purpose                                      | Key functions/classes              |
|-----------------------------------|----------------------------------------------|------------------------------------|
| `main.py`                         | ASGI app creation, middleware, startup        | `app`, `health_check()`           |
| `config/settings.py`             | Environment configuration                    | `Settings`, `get_settings()`      |
| `core/logger.py`                 | Logging factory                              | `get_logger(name)`                |
| `core/llm_provider.py`           | Singleton LLM wrapper                        | `LLMProvider`, `get_llm()`        |
| `workflows/base_workflow.py`     | Abstract base class for all workflows        | `BaseWorkflow`, `run()`           |
| `workflows/test_search/config.py`| System prompts and tool definitions          | `SEARCH_AGENT_SYSTEM_PROMPT`, `TOOLS` |
| `workflows/test_search/agents.py`| Agent factory                                | `create_search_agent()`           |
| `workflows/test_search/nodes.py` | Graph node functions                         | `SearchNodes` class               |
| `workflows/test_search/graph.py` | LangGraph wiring + concrete workflow         | `TestSearchWorkflow`, `SearchWorkflowState` |
| `api/models.py`                  | Pydantic request/response schemas            | `WorkflowRequest`, `WorkflowResponse` |
| `api/routes.py`                  | FastAPI endpoints + workflow registry         | `WORKFLOWS`, `execute_workflow()` |

---

## Configuration Management

### How settings work

1. `pydantic-settings` reads `.env` file on first `get_settings()` call.
2. Environment variables **override** `.env` values.
3. Defaults in the `Settings` class are used if neither `.env` nor env-vars provide a value.

**Override precedence:** Environment variable > `.env` file > class default.

### Adding a new setting

```python
# 1. Add to Settings class in config/settings.py
class Settings(BaseSettings):
    MY_NEW_SETTING: str = "default_value"

# 2. Add to .env and .env.example
MY_NEW_SETTING=custom_value

# 3. Use in your code
settings = get_settings()
value = settings.MY_NEW_SETTING
```

---

## Logging Strategy

### What gets logged

| Event                         | Level   | Module          |
|-------------------------------|---------|-----------------|
| Workflow start/end            | INFO    | `base_workflow`  |
| Execution time                | INFO    | `base_workflow`  |
| State initialisation          | INFO    | `graph.py`       |
| Node entry/exit               | INFO    | `nodes.py`       |
| Tool invocations              | INFO    | `config.py`      |
| Agent creation                | INFO    | `agents.py`      |
| LLM initialisation            | INFO    | `llm_provider`   |
| Validation warnings           | WARNING | various         |
| Unhandled exceptions          | ERROR   | various         |
| Critical failures (LLM init)  | CRITICAL| `llm_provider`   |

### Log format

```
2025-01-15 12:30:45 | workflows.TestSearchWorkflow | INFO     | ▶ Running workflow: Test Search Workflow
2025-01-15 12:30:45 | workflows.test_search.nodes.SearchNodes | INFO     | ── search_node: START ──
```

### Using the logger

```python
from core.logger import get_logger

logger = get_logger(__name__)  # pass __name__ for automatic module naming
logger.info("Processing %d items", count)
logger.error("Failed: %s", exc, exc_info=True)  # includes traceback
```

---

## Error Handling

### Exception hierarchy

```
Exception
├── ValueError          → 400 Bad Request (client input error)
├── HTTPException(404)  → 404 Not Found (unknown workflow)
├── RuntimeError        → 500 Internal Server Error (code bug)
└── Exception (catch-all) → 500 (unexpected failure)
```

### Error propagation

```
Tool raises ValueError
    → Agent sees error as "observation" → retries or reports
        → Node catches Exception → returns error state
            → BaseWorkflow.run() catches → logs + re-raises
                → routes.py catches → maps to HTTP status
                    → Client receives structured error JSON
```

### Recovery strategies

| Component   | Strategy                                                |
|-------------|---------------------------------------------------------|
| Tools       | Validate input, return readable error strings           |
| Agents      | `handle_parsing_errors=True` auto-retries on bad output |
| Nodes       | Catch exceptions, return error state (don't crash graph) |
| BaseWorkflow| Log with traceback, re-raise to API layer               |
| API routes  | Map exception types to HTTP status codes                 |

---

## Extending the Project

### Step-by-step: Add a new workflow

```
Step 1: Create folder         workflows/my_workflow/
Step 2: Write __init__.py     Package docstring
Step 3: Write config.py       System prompt + @tool functions + TOOLS list
Step 4: Write agents.py       create_my_agent() → AgentExecutor
Step 5: Write nodes.py        MyNodes class with async node methods
Step 6: Write graph.py        MyWorkflowState TypedDict + MyWorkflow(BaseWorkflow)
Step 7: Register              WORKFLOWS["my_workflow"] = MyWorkflow()  in api/routes.py
Step 8: Test                  POST /api/execute/my_workflow
```

### Template for a new workflow's `graph.py`

```python
from typing import Any, Dict
from typing_extensions import TypedDict
from langgraph.graph import StateGraph, END
from workflows.base_workflow import BaseWorkflow

class MyState(TypedDict, total=False):
    input_field: str
    result: dict
    status: str

class MyWorkflow(BaseWorkflow):
    def __init__(self):
        super().__init__(name="My Workflow", description="Does X")

    def build_graph(self):
        # Create nodes, wire graph, compile, return
        graph = StateGraph(MyState)
        graph.add_node("step1", self._step1)
        graph.add_edge("step1", END)
        graph.set_entry_point("step1")
        return graph.compile()

    async def _step1(self, state):
        return {"result": {"data": "..."}, "status": "done"}

    def initialize_state(self, input_data):
        return {"input_field": input_data["field"], "status": "init"}

    def extract_result(self, final_state):
        return final_state.get("result", {})
```

### How to add new tools

```python
# In your workflow's config.py
from langchain_core.tools import tool

@tool
def my_new_tool(arg: str) -> str:
    """Description the LLM reads to decide when to use this tool."""
    # Your implementation
    return result

TOOLS = [existing_tool, my_new_tool]  # Add to the list
```

### How to register workflows in API

```python
# In api/routes.py — add import + dict entry
from workflows.my_workflow.graph import MyWorkflow

WORKFLOWS: Dict[str, object] = {
    "test_search": TestSearchWorkflow(),
    "my_workflow": MyWorkflow(),  # ← one line
}
```

### Plugin/Extension points

| Extension point          | How to extend                                      |
|--------------------------|----------------------------------------------------|
| New workflow             | Add package under `workflows/`, register in routes |
| New tool for agent       | Add `@tool` function in config.py, add to TOOLS   |
| New LLM provider         | Modify `LLMProvider._initialise_llm()`            |
| New middleware            | `app.add_middleware(...)` in `main.py`             |
| Authentication            | Add FastAPI `Depends()` to route decorators        |
| Database integration      | Add connection in `core/`, inject via settings     |

---

## Before You Code Checklist

Before creating a new workflow, verify:

- [ ] **Unique name** — the workflow key doesn't conflict with existing entries in `WORKFLOWS`.
- [ ] **State schema** — you've defined a `TypedDict` with all fields any node will read/write.
- [ ] **Tools tested** — your `@tool` functions work independently before wiring them into agents.
- [ ] **System prompt** — clear role, constraints, and output format in `SEARCH_AGENT_SYSTEM_PROMPT`.
- [ ] **Error handling** — every node has `try/except` that returns error state (not crashes).
- [ ] **Logging** — `get_logger(__name__)` is used; INFO on start/end, ERROR on failures.
- [ ] **Type hints** — every function has parameter and return type annotations.
- [ ] **Docstrings** — every class and public function has a docstring explaining *why*.
- [ ] **Registered** — the workflow is added to `WORKFLOWS` in `api/routes.py`.
- [ ] **Tested** — you can `curl` the endpoint and get a valid response.

---

## Common Tasks

### Running the application

```bash
# Development (with auto-reload)
DEBUG=True python main.py

# Production
uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
```

### Adding a new workflow

See [Extending the Project](#extending-the-project) above.

### Modifying agent behaviour

Edit the system prompt in `workflows/<name>/config.py`:

```python
SYSTEM_PROMPT = """
You are a ... (modify persona, constraints, output format)
"""
```

### Changing LLM model

Option 1 — environment variable:
```bash
OPENAI_MODEL=gpt-4o python main.py
```

Option 2 — `.env` file:
```
OPENAI_MODEL=gpt-4o
```

### Debugging a workflow

```bash
# 1. Set log level to DEBUG
LOG_LEVEL=DEBUG python main.py

# 2. Watch for tool invocations and agent reasoning in logs

# 3. Check AgentExecutor verbose output (verbose=True in agents.py)
```

### Adding authentication

```python
# In api/routes.py — add a dependency
from fastapi import Depends, Header, HTTPException

async def verify_api_key(x_api_key: str = Header(...)):
    if x_api_key != settings.API_SECRET_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return x_api_key

@router.post("/execute/{workflow_name}", dependencies=[Depends(verify_api_key)])
async def execute_workflow(...):
    ...
```

---

## Common Mistakes

### ❌ Forgetting `total=False` on TypedDict

```python
# WRONG — all fields required at creation → crash on initialize_state
class MyState(TypedDict):
    query: str
    result: dict  # doesn't exist yet!

# CORRECT — fields are optional initially
class MyState(TypedDict, total=False):
    query: str
    result: dict
```

### ❌ Returning full state from nodes

```python
# WRONG — overwrites all other state keys
async def my_node(state: dict) -> dict:
    return state  # copies entire state including stale data

# CORRECT — return only the keys you changed
async def my_node(state: dict) -> dict:
    return {"my_output": "...", "status": "done"}
```

### ❌ Creating a new LLMProvider instance per request

```python
# WRONG — defeats the singleton; creates a new ChatOpenAI each time
llm = ChatOpenAI(model="gpt-4o-mini", api_key=key)

# CORRECT — reuses the singleton
llm = LLMProvider().get_llm()
```

### ❌ Missing `agent_scratchpad` in prompt

```python
# WRONG — agent can't track its reasoning history
prompt = ChatPromptTemplate.from_messages([
    ("system", PROMPT),
    ("human", "{input}"),
])

# CORRECT — includes scratchpad for ReAct loop
prompt = ChatPromptTemplate.from_messages([
    ("system", PROMPT),
    ("human", "{input}"),
    MessagesPlaceholder(variable_name="agent_scratchpad"),
])
```

### ❌ Blocking the event loop with synchronous code

```python
# WRONG — blocks the entire server during LLM call
result = agent.invoke({"input": query})

# CORRECT — non-blocking async call
result = await agent.ainvoke({"input": query})
```

### ❌ Swallowing exceptions silently

```python
# WRONG — error disappears
try:
    result = await agent.ainvoke(...)
except Exception:
    pass

# CORRECT — log and return error state
try:
    result = await agent.ainvoke(...)
except Exception as exc:
    logger.error("Failed: %s", exc, exc_info=True)
    return {"status": "error", "error": str(exc)}
```

---

## Testing Guidelines

### Unit testing workflows

```python
# tests/test_test_search.py
import pytest
from workflows.test_search.graph import TestSearchWorkflow

@pytest.fixture
def workflow():
    return TestSearchWorkflow()

def test_initialize_state_valid(workflow):
    state = workflow.initialize_state({"query": "OWASP"})
    assert state["query"] == "OWASP"
    assert state["status"] == "initialized"

def test_initialize_state_empty_query(workflow):
    with pytest.raises(ValueError):
        workflow.initialize_state({"query": ""})
```

### Integration testing endpoints

```python
# tests/test_api.py
import pytest
from httpx import AsyncClient
from main import app

@pytest.mark.asyncio
async def test_health():
    async with AsyncClient(app=app, base_url="http://test") as client:
        resp = await client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"

@pytest.mark.asyncio
async def test_list_workflows():
    async with AsyncClient(app=app, base_url="http://test") as client:
        resp = await client.get("/api/workflows")
        assert resp.status_code == 200
        workflows = resp.json()["workflows"]
        assert any(w["key"] == "test_search" for w in workflows)
```

### Testing tools independently

```python
from workflows.test_search.config import search_information

def test_search_information():
    result = search_information.invoke("OWASP")
    assert "OWASP" in result
    assert len(result) > 0

def test_search_information_empty():
    with pytest.raises(ValueError):
        search_information.invoke("")
```

---

## Deployment Considerations

### Production checklist

- [ ] Set `DEBUG=False`
- [ ] Set a real `OPENAI_API_KEY`
- [ ] Restrict CORS origins to actual frontend domain(s)
- [ ] Use `uvicorn main:app --workers 4` for concurrency
- [ ] Set `LOG_LEVEL=WARNING` to reduce log volume
- [ ] Add rate limiting middleware (e.g. `slowapi`)
- [ ] Add authentication (API key or OAuth2)
- [ ] Monitor with Prometheus/Grafana or cloud-native tools
- [ ] Use a reverse proxy (nginx/Caddy) for TLS termination

### Docker deployment

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
```

### Scalability notes

- **Stateless** — no in-memory session state; can run behind a load balancer.
- **Async** — I/O-bound LLM calls don't block the event loop.
- **Multi-worker** — Uvicorn with `--workers N` for CPU-bound work.
- **Horizontal scaling** — deploy multiple containers behind a load balancer.

### Security hardening

- Store API keys in a secrets manager (AWS Secrets Manager, Vault).
- Enable HTTPS via TLS certificates (Let's Encrypt + nginx).
- Add request logging with correlation IDs for audit trails.
- Validate and sanitise all user input before passing to LLMs.

---

## Troubleshooting

| Symptom                            | Likely cause                    | Fix                                     |
|------------------------------------|---------------------------------|-----------------------------------------|
| `OPENAI_API_KEY is not set`        | Missing or placeholder key      | Set real key in `.env`                  |
| `ModuleNotFoundError: langchain`   | Dependencies not installed      | `pip install -r requirements.txt`       |
| Port 8000 in use                   | Another process on same port    | `API_PORT=8001` or kill the process     |
| Agent loops forever                | Bad tool output or prompt       | Check `max_iterations`, review prompt   |
| `TypeError: not an abstract class` | Missing abstract method impl    | Implement all `@abstractmethod`s        |
| CORS error in browser              | Frontend origin not allowed     | Add origin to `allow_origins` list      |
| 422 Unprocessable Entity           | Bad request schema              | Check Swagger docs for expected body    |
| Slow responses (>30s)              | Large model or complex query    | Use `gpt-4o-mini`, reduce prompt size   |
| `RuntimeError: Graph not compiled` | `build_graph()` returned None   | Ensure you return `graph.compile()`     |

---

## Future Enhancements

| Enhancement                 | Priority | Complexity | Description                                   |
|-----------------------------|----------|------------|-----------------------------------------------|
| Vector DB integration       | High     | Medium     | Replace stub search with ChromaDB/Pinecone    |
| Authentication              | High     | Low        | API key or JWT middleware                      |
| WebSocket streaming         | Medium   | Medium     | Stream agent reasoning to UI in real time      |
| Conditional graph edges     | Medium   | Low        | Branch workflow based on intermediate results  |
| Parallel node execution     | Medium   | Medium     | Fan-out/fan-in for independent assessments     |
| Result caching              | Low      | Low        | Cache LLM responses for identical queries      |
| Workflow persistence        | Low      | High       | Save/resume workflows across server restarts   |
| Multi-model support         | Low      | Medium     | Use different models for different workflows   |
| Rate limiting               | High     | Low        | Prevent API abuse with `slowapi`              |
| Observability (tracing)     | Medium   | Medium     | LangSmith or OpenTelemetry integration        |

---

## Glossary

| Term              | Definition                                                                       |
|-------------------|----------------------------------------------------------------------------------|
| **Agent**         | LLM + tools + reasoning loop; can decide *which* tool to call                    |
| **ASGI**          | Asynchronous Server Gateway Interface; the protocol Uvicorn/FastAPI speak        |
| **BaseWorkflow**  | Abstract class defining the `run()` lifecycle; all workflows inherit from it      |
| **Graph**         | A directed graph of nodes; defines the execution order of a workflow             |
| **LangChain**     | Python framework for building applications powered by language models            |
| **LangGraph**     | Extension of LangChain for stateful, graph-based workflows                       |
| **Node**          | An async function in a graph that reads/writes state                             |
| **ReAct**         | Reasoning + Acting; a prompting framework where the LLM thinks, acts, observes   |
| **Registry**      | A dict mapping names to objects; used for workflow discovery                      |
| **Singleton**     | A class that ensures only one instance exists                                    |
| **State**         | A `TypedDict` dict that flows through the graph, modified by each node           |
| **Tool**          | A Python function that an agent can call; decorated with `@tool`                 |
| **TypedDict**     | A dict with type annotations; used for static type checking without runtime cost |
| **Workflow**      | A self-contained assessment pipeline: config + agents + nodes + graph            |

---

## Quick Reference

### API endpoints

```
GET  /health                        → HealthResponse
GET  /api/workflows                 → {workflows: [...]}
POST /api/execute/{workflow_name}   → WorkflowResponse
```

### Key classes

```python
from config import Settings               # Configuration (pydantic-settings)
from core import get_logger, LLMProvider   # Logging + singleton LLM
from workflows import BaseWorkflow         # Abstract workflow base class
from api.models import WorkflowRequest     # Request schema
from api.models import WorkflowResponse    # Response schema
```

### Curl examples

```bash
# Health check
curl http://localhost:8000/health

# List workflows
curl http://localhost:8000/api/workflows

# Execute workflow
curl -X POST http://localhost:8000/api/execute/test_search \
  -H "Content-Type: application/json" \
  -d '{"input_data": {"query": "CI/CD security"}}'
```

### Python client example

```python
import requests

BASE_URL = "http://localhost:8000"

# Health
print(requests.get(f"{BASE_URL}/health").json())

# List
print(requests.get(f"{BASE_URL}/api/workflows").json())

# Execute
response = requests.post(
    f"{BASE_URL}/api/execute/test_search",
    json={"input_data": {"query": "Container security best practices"}}
)
print(response.json())
```

---

## Version History

| Version | Date       | Changes                                        |
|---------|------------|-------------------------------------------------|
| 1.0.0   | 2025-06-15 | Initial release — test_search workflow, FastAPI  |
|         |            | API, LangChain agents, LangGraph state machine   |

*Maintain this table when making significant changes.*

---

> **This document is a living reference.**  Update it whenever you add a
> workflow, change architecture, or introduce new patterns.
