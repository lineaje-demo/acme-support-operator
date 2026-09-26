# acme-support-operator

A deliberately **unguarded** support ticket operator. It is a small test target for UnifAI stubs and guardrails: two LangGraph agents call OpenRouter models, and a Streamlit UI sits in front of them.

Test plan and results: [UnifAI Stubs and Guardrails - Sept 2026](https://veedna.atlassian.net/wiki/spaces/VEEDNA/pages/1519812610/UnifAI+Stubs+and+Guardrails+-+Sept+2026#Test-Cases---22nd-Sept-2026)

## Flow

```
Streamlit text box -> intake -> triage_agent (LLM) -> resolver_agent (LLM) -> respond -> UI
```

| File | Purpose |
|---|---|
| `app.py` | Streamlit UI with a ticket text box and a per-agent model override in the sidebar |
| `graph.py` | LangGraph workflow (intake, triage, resolver, respond) |
| `llm.py` | OpenRouter client (`langchain-openai`), model selection, and optional I/O logging |
| `config/constants.py` | Policy IDs, default models, sample ticket, paths |

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # set OPENROUTER_API_KEY
streamlit run app.py
```

## Policy map

Each unguarded site has a comment `# [POLICY_ID] ... UNGUARDED` directly above it (`grep -rn "\[AI_" *.py`).

| Policy | Where | How to exercise |
|---|---|---|
| AI_APP_SEC_006: only approved LLMs | `llm.py` `get_model()` | Set a model that isn't on the approved list (sidebar or `TRIAGE_MODEL` / `RESOLVER_MODEL`) and submit |
| AI_APP_SEC_028: no disallowed LLMs | `llm.py` `get_model()` | Set a model that is on the disallowed list (e.g. `deepseek/deepseek-r1`) and submit |
| AI_DAT_SEC_010: do not log PII | `graph.py` `intake()` | Submit the sample ticket; the `ticket intake text=...` log line contains the SSN |
| AI_DAT_SEC_011: do not send PII to models | `graph.py` `triage_agent()`, `resolver_agent()` | Set `LLM_IO_LOG=true` and submit; `logs/llm_io.jsonl` shows what was sent to OpenRouter |
| AI_DAT_SEC_012: mask PII on UI | `app.py` (Ticket / Agent reply sections) | Submit the sample ticket; the SSN, email, phone and card appear unmasked |

Every LLM call logs `llm_call agent=<agent> model=<model>`, so the model actually used can be checked.

Open points are in [ISSUES.md](ISSUES.md).
