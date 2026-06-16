# DevSecOps Assessment Backend

> Production-ready, agentic AI backend for automated DevSecOps assessments —
> powered by **LangChain**, **LangGraph**, and **FastAPI**.

---

## Table of Contents

- [Project Overview](#project-overview)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Configuration](#configuration)
- [API Documentation](#api-documentation)
- [Creating New Workflows](#creating-new-workflows)
- [Project Structure](#project-structure)
- [Design Patterns](#design-patterns)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

---

## Project Overview

This backend provides an **extensible workflow engine** for running DevSecOps
assessments.  Each assessment is modelled as a **LangGraph state machine**
whose nodes are powered by **LangChain agents** with tool access.

**Key capabilities:**

| Feature                  | Description                                              |
|--------------------------|----------------------------------------------------------|
| Agentic AI               | LangChain ReAct agents with OpenAI function calling      |
| Stateful workflows       | LangGraph directed-graph state machines                  |
| RESTful API              | FastAPI with auto-generated Swagger docs                 |
| Workflow isolation        | One package per workflow — no cross-contamination        |
| Scalable registry        | Add new workflows with a single dict entry               |
| Production-ready         | Logging, error handling, health checks, CORS, `.env`     |

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        HTTP Clients                              │
│               (curl, Python requests, Postman, UI)               │
└────────────────────────────┬─────────────────────────────────────┘
                             │  HTTP
                             ▼
┌──────────────────────────────────────────────────────────────────┐
│                      FastAPI Application                         │
│  ┌────────────┐  ┌──────────────┐  ┌──────────────────────────┐ │
│  │ /health    │  │ /api/execute │  │ /api/workflows           │ │
│  │ (system)   │  │ /{name}      │  │ (listing)                │ │
│  └────────────┘  └──────┬───────┘  └──────────────────────────┘ │
│                         │                                        │
│              ┌──────────▼──────────┐                             │
│              │  Workflow Registry   │                             │
│              │  (WORKFLOWS dict)   │                             │
│              └──────────┬──────────┘                             │
└─────────────────────────┼────────────────────────────────────────┘
                          │
              ┌───────────▼───────────┐
              │    BaseWorkflow       │
              │  ┌─────────────────┐  │
              │  │ initialize_state│  │
              │  │ build_graph     │  │
              │  │ extract_result  │  │
              │  │ run()           │  │
              │  └─────────────────┘  │
              └───────────┬───────────┘
                          │ inherits
              ┌───────────▼───────────┐
              │  TestSearchWorkflow   │
              │  ┌─────────────────┐  │
              │  │ StateGraph      │  │
              │  │  search → proc  │  │
              │  │  → END          │  │
              │  └────────┬────────┘  │
              └───────────┼───────────┘
                          │
            ┌─────────────┼──────────────┐
            │             │              │
     ┌──────▼───┐  ┌──────▼───┐  ┌───────▼──────┐
     │  Agents  │  │  Nodes   │  │  Tools       │
     │ (ReAct)  │  │ (funcs)  │  │ (search_…)   │
     └──────┬───┘  └──────────┘  └──────────────┘
            │
     ┌──────▼───────────┐
     │  LLM Provider    │
     │  (Singleton)     │
     │  ChatOpenAI      │
     └──────────────────┘
            │
     ┌──────▼───────────┐
     │  OpenAI API      │
     └──────────────────┘
```

---

## Quick Start

```bash
# 1. Clone the repository
git clone <repo-url>
cd devops-assessment-backend

# 2. Create a virtual environment
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment
cp .env.example .env
# Edit .env and set your OPENAI_API_KEY

# 5. Start the server
python main.py
# → Server running at http://0.0.0.0:8000
# → Swagger docs at http://0.0.0.0:8000/docs
```

### First API call

```bash
# Execute the test_search workflow
curl -X POST http://localhost:8000/api/execute/test_search \
  -H "Content-Type: application/json" \
  -d '{"input_data": {"query": "OWASP Top-10 vulnerabilities"}}'
```

Expected response:

```json
{
  "workflow": "test_search",
  "status": "success",
  "result": {
    "query": "OWASP Top-10 vulnerabilities",
    "assessment": "...",
    "search_successful": true,
    "metadata": {
      "workflow": "test_search",
      "status": "completed"
    }
  },
  "error": null,
  "timestamp": "2025-01-15T12:30:45.123456"
}
```

---

## Installation

### Prerequisites

| Requirement      | Version | Notes                              |
|------------------|---------|------------------------------------|
| Python           | 3.10+   | 3.11 or 3.12 recommended          |
| pip              | 23.0+   | `pip install --upgrade pip`        |
| OpenAI API key   | —       | https://platform.openai.com       |

### Step-by-step

```bash
# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate        # Linux / macOS
.venv\Scripts\activate           # Windows

# Install pinned dependencies
pip install -r requirements.txt

# Verify installation
python -c "import fastapi; import langchain; print('OK')"
```

---

## Configuration

All configuration is managed via environment variables (or `.env` file).

| Variable            | Default          | Description                               |
|---------------------|------------------|-------------------------------------------|
| `OPENAI_API_KEY`    | `your_api_key…`  | OpenAI API key (required)                 |
| `OPENAI_MODEL`      | `gpt-4o-mini`    | Model identifier                          |
| `API_HOST`          | `0.0.0.0`        | Server bind address                       |
| `API_PORT`          | `8000`           | Server port                               |
| `DEBUG`             | `False`          | Enable debug mode (auto-reload)           |
| `LOG_LEVEL`         | `INFO`           | Logging verbosity                         |

**Security note:** Never commit `.env` with real API keys. Use `.env.example` as a template.

---

## API Documentation

### Interactive docs

Once the server is running, visit:

- **Swagger UI:** http://localhost:8000/docs
- **ReDoc:** http://localhost:8000/redoc
- **OpenAPI JSON:** http://localhost:8000/openapi.json

### Endpoints

#### `GET /health`

Health check for load balancers and monitoring.

```bash
curl http://localhost:8000/health
```

```json
{
  "status": "healthy",
  "app_name": "DevSecOps Assessment Backend",
  "version": "1.0.0",
  "timestamp": "2025-01-15T12:30:45.123456"
}
```

#### `GET /api/workflows`

List all registered workflows.

```bash
curl http://localhost:8000/api/workflows
```

```json
{
  "workflows": [
    {
      "name": "Test Search Workflow",
      "description": "Search and analyse DevSecOps-related information…",
      "key": "test_search"
    }
  ]
}
```

#### `POST /api/execute/{workflow_name}`

Execute a workflow.

```bash
curl -X POST http://localhost:8000/api/execute/test_search \
  -H "Content-Type: application/json" \
  -d '{"input_data": {"query": "Container security best practices"}}'
```

**Python example:**

```python
import requests

response = requests.post(
    "http://localhost:8000/api/execute/test_search",
    json={"input_data": {"query": "CI/CD pipeline security"}}
)
print(response.json())
```

**Error responses:**

| Status | Cause                         | Example                           |
|--------|-------------------------------|-----------------------------------|
| 400    | Invalid input data            | Missing `query` field             |
| 404    | Unknown workflow name         | `/api/execute/nonexistent`        |
| 422    | Malformed JSON body           | Invalid Pydantic schema           |
| 500    | Unexpected server error       | LLM timeout, internal bug         |

---

## Creating New Workflows

### Step 1: Create the workflow package

```
workflows/
  my_workflow/
    __init__.py    ← docstring describing the workflow
    config.py      ← system prompts + tool definitions
    agents.py      ← agent factory function
    nodes.py       ← graph node functions
    graph.py       ← StateGraph wiring + Workflow class
```

### Step 2: Define the state schema

```python
# workflows/my_workflow/graph.py
from typing_extensions import TypedDict

class MyWorkflowState(TypedDict, total=False):
    input_field: str
    intermediate_data: str
    final_result: dict
    status: str
```

### Step 3: Create tools and prompts

```python
# workflows/my_workflow/config.py
from langchain_core.tools import tool

SYSTEM_PROMPT = "You are a ..."

@tool
def my_tool(arg: str) -> str:
    """Tool description for the LLM."""
    return f"Result for {arg}"

TOOLS = [my_tool]
```

### Step 4: Create the agent

```python
# workflows/my_workflow/agents.py
from langchain.agents import AgentExecutor, create_openai_functions_agent
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from core.llm_provider import LLMProvider
from workflows.my_workflow.config import SYSTEM_PROMPT, TOOLS

def create_my_agent() -> AgentExecutor:
    llm = LLMProvider().get_llm()
    prompt = ChatPromptTemplate.from_messages([
        ("system", SYSTEM_PROMPT),
        ("human", "{input}"),
        MessagesPlaceholder(variable_name="agent_scratchpad"),
    ])
    agent = create_openai_functions_agent(llm=llm, tools=TOOLS, prompt=prompt)
    return AgentExecutor(agent=agent, tools=TOOLS, max_iterations=10)
```

### Step 5: Implement nodes

```python
# workflows/my_workflow/nodes.py
class MyNodes:
    def __init__(self):
        self.agent = create_my_agent()

    async def my_node(self, state: dict) -> dict:
        result = await self.agent.ainvoke({"input": state["input_field"]})
        return {"intermediate_data": result["output"], "status": "done"}
```

### Step 6: Wire the graph

```python
# workflows/my_workflow/graph.py
from langgraph.graph import StateGraph, END
from workflows.base_workflow import BaseWorkflow

class MyWorkflow(BaseWorkflow):
    def __init__(self):
        super().__init__(name="My Workflow", description="Does X")

    def build_graph(self):
        nodes = MyNodes()
        graph = StateGraph(MyWorkflowState)
        graph.add_node("step1", nodes.my_node)
        graph.add_edge("step1", END)
        graph.set_entry_point("step1")
        return graph.compile()

    def initialize_state(self, input_data):
        return {"input_field": input_data["field"], "status": "init"}

    def extract_result(self, final_state):
        return final_state.get("final_result", {})
```

### Step 7: Register in the API

```python
# api/routes.py — add one line
from workflows.my_workflow.graph import MyWorkflow

WORKFLOWS: Dict[str, object] = {
    "test_search": TestSearchWorkflow(),
    "my_workflow": MyWorkflow(),          # ← new
}
```

### Step 8: Restart and test

```bash
python main.py
curl -X POST http://localhost:8000/api/execute/my_workflow \
  -H "Content-Type: application/json" \
  -d '{"input_data": {"field": "value"}}'
```

---

## Project Structure

```
devops-assessment-backend/
├── config/                    # ── Configuration layer
│   ├── __init__.py            #    Re-exports Settings
│   └── settings.py            #    Pydantic-settings with .env support
│
├── core/                      # ── Cross-cutting infrastructure
│   ├── __init__.py            #    Re-exports logger + LLMProvider
│   ├── logger.py              #    Structured logging factory
│   └── llm_provider.py        #    Singleton ChatOpenAI wrapper
│
├── workflows/                 # ── Business logic (one pkg per workflow)
│   ├── __init__.py            #    Re-exports BaseWorkflow
│   ├── base_workflow.py       #    Abstract base with run() lifecycle
│   └── test_search/           #    Reference workflow implementation
│       ├── __init__.py        #    Package docstring
│       ├── config.py          #    Prompts + tool definitions
│       ├── agents.py          #    Agent factory (ReAct + tools)
│       ├── nodes.py           #    Graph node functions
│       └── graph.py           #    LangGraph wiring + state schema
│
├── api/                       # ── HTTP interface
│   ├── __init__.py            #    Package docstring
│   ├── models.py              #    Pydantic request/response models
│   └── routes.py              #    FastAPI routes + workflow registry
│
├── main.py                    # ── Application entry point
├── requirements.txt           # ── Pinned dependencies
├── .env                       # ── Runtime configuration (git-ignored)
├── .env.example               # ── Configuration template (committed)
├── .gitignore                 # ── Git ignore rules
├── README.md                  # ── This file
└── PROJECT_CONTEXT.md         # ── Deep-dive context for developers
```

---

## Design Patterns

### 1. Singleton Pattern — `LLMProvider`

**Problem:** Creating a new `ChatOpenAI` instance per request wastes TCP connections and risks configuration drift.

**Solution:** `LLMProvider.__new__()` ensures only one instance exists. All modules share the same LLM client.

### 2. Abstract Base Class — `BaseWorkflow`

**Problem:** Workflows need a consistent lifecycle (init → run → extract) but have different internal logic.

**Solution:** `BaseWorkflow` defines the template method (`run()`) and delegates specifics to abstract hooks.

### 3. Factory Pattern — Agent Creation

**Problem:** Agent construction requires wiring LLM + tools + prompt + executor — complex and error-prone if repeated.

**Solution:** `create_search_agent()` encapsulates construction, returning a ready-to-use `AgentExecutor`.

### 4. Registry Pattern — `WORKFLOWS` dict

**Problem:** The API needs to look up workflows by name without hard-coding route handlers per workflow.

**Solution:** A simple `dict[str, BaseWorkflow]` maps names to instances. Adding a workflow = adding one dict entry.

### 5. Dependency Injection — Configuration

**Problem:** Hard-coded values (API keys, ports) make code untestable and environment-specific.

**Solution:** `get_settings()` reads from `.env` / environment. Swap values without touching code.

---

## Troubleshooting

| Issue                                  | Solution                                              |
|----------------------------------------|-------------------------------------------------------|
| `OPENAI_API_KEY is not set` warning    | Set your real key in `.env`                           |
| `ModuleNotFoundError`                  | Activate your virtual env, run `pip install -r …`     |
| Port 8000 already in use               | Change `API_PORT` in `.env` or kill the other process |
| Agent enters infinite loop             | `max_iterations=10` prevents this; check tool outputs |
| 422 Unprocessable Entity               | Request body doesn't match `WorkflowRequest` schema   |
| `RuntimeError: Graph not compiled`     | Check `build_graph()` returns the compiled graph      |
| Slow responses                         | Use `gpt-4o-mini` instead of `gpt-4o`                |
| CORS errors from browser               | `allow_origins=["*"]` is set — check URL correctness  |

---

## Contributing

1. **Fork** the repository.
2. **Create a feature branch:** `git checkout -b feature/my-workflow`
3. **Follow the structure:** One workflow per package under `workflows/`.
4. **Add tests:** (future) pytest + httpx for endpoint testing.
5. **Document:** Update this README and `PROJECT_CONTEXT.md`.
6. **Submit a PR** with a clear description of changes.

### Code style

- Python 3.10+ type hints everywhere.
- PEP 8 compliance (use `ruff` or `black`).
- Docstrings on every public function and class.
- Inline comments explaining *why*, not *what*.

---

## License

This project is provided as-is for internal use.  Add your preferred
open-source license here (MIT, Apache 2.0, etc.).
