# Technology Stack Decision

## Decision

Use **Python + LangChain + LangGraph for agent orchestration** and **Rust for security-critical enforcement**. Keep Python for the evaluation harness and as an optional untrusted workload runtime in Docker.

## Rationale

- Python has the mature LLM integration and evaluation ecosystem needed for rapid agent development. LangChain provides model/tool/structured-output integrations; LangGraph provides explicit stateful orchestration, deterministic routing and human-in-the-loop control.
- Rust is better suited to the trusted policy/ratchet and native Linux launcher because it provides memory safety and systems-level control while allowing narrow, reviewable syscall integration.
- A language boundary reinforces separation of duties: the model proposes; Rust authorizes and enforces; Docker contains the worker.

## Authority rule

The Rust policy/ratchet implementation is the only authoritative source for permission decisions. Python can validate requests defensively and orchestrate calls, but cannot grant permissions or override Rust decisions.

## Agent construction decision

Use a **custom LangGraph `StateGraph`** as the top-level task workflow. Use LangChain for chat-model/provider adapters, prompt composition, Pydantic structured output and narrow proposal-tool schemas. The planner returns typed proposals; explicit LangGraph nodes perform validation, call the Rust authority, pause for approval and dispatch approved work. Do not start with a generic autonomous shell/tool loop. A LangChain `create_agent` subgraph may be evaluated later, but only if every tool call still passes through the same Rust authorization gate.

This choice uses LangGraph for the deterministic-plus-agentic workflow control that this security project requires, while retaining LangChain's model and tool integration layer. See the [LangChain Python reference](https://reference.langchain.com/python/langgraph) and [LangGraph overview](https://reference.langchain.com/python/langgraph/overview).

## Privacy defaults

Use local controller/Rust communication, minimal graph state and local checkpointing only when required. LangSmith tracing is disabled by default pending privacy review. Workers receive no model credentials or Docker socket.

## Trade-off

The hybrid design introduces a Python/Rust protocol and two build toolchains. Keep the protocol versioned, typed and small; test serialization, stale policy hashes, failure handling and authorization on every request.
