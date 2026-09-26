"""LangGraph workflow for the support ticket operator.

intake -> triage_agent -> resolver_agent -> respond
"""

import json
import logging
import re
from typing import TypedDict

from langchain_core.messages import HumanMessage, SystemMessage
from langgraph.graph import END, START, StateGraph

import llm
from config.constants import TICKET_CATEGORIES, TICKET_PRIORITIES

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# PII / secret redaction helpers
# ---------------------------------------------------------------------------
_PII_PATTERNS: list[tuple[str, str]] = [
    # Social Security Number  (e.g. 123-45-6789 / 123 45 6789 / 123456789)
    (r"\b(?!000|666|9\d{2})\d{3}[- ]?(?!00)\d{2}[- ]?(?!0000)\d{4}\b", "[REDACTED-SSN]"),
    # Credit / debit card numbers (13-19 digits, optionally space/dash separated)
    (r"\b(?:\d[ -]?){13,19}\b", "[REDACTED-CARD]"),
    # Email addresses
    (r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", "[REDACTED-EMAIL]"),
    # Personal phone numbers (various formats)
    (r"(?:\+?1[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}\b", "[REDACTED-PHONE]"),
    # IP addresses (v4)
    (r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "[REDACTED-IP]"),
    # MAC addresses
    (r"\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b", "[REDACTED-MAC]"),
    # AWS access key IDs
    (r"\b(AKIA|ASIA|AROA|AIDA|ANPA|ANVA|APKA)[A-Z0-9]{16}\b", "[REDACTED-AWS-KEY]"),
    # AWS secret access keys (40-char base64-ish strings following common label)
    (r"(?i)(?:aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key|aws[_\-\s]?token)[\s:=]+[A-Za-z0-9/+]{40}", "[REDACTED-AWS-SECRET]"),
    # GCP / Google API keys
    (r"AIza[0-9A-Za-z\-_]{35}", "[REDACTED-GCP-KEY]"),
    # Azure SAS / storage keys (base64, 88 chars ending ==)
    (r"[A-Za-z0-9+/]{86}==", "[REDACTED-AZURE-KEY]"),
    # Generic Bearer / OAuth tokens
    (r"(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*", "[REDACTED-BEARER-TOKEN]"),
    # Generic password/secret/token assignments in text
    (r"(?i)(?:password|passwd|secret|token|api[_\-]?key|auth[_\-]?key|access[_\-]?key)[\s:=]+\S+", "[REDACTED-CREDENTIAL]"),
    # Passport numbers (generic: letter(s) + 6-9 digits)
    (r"\b[A-Z]{1,2}\d{6,9}\b", "[REDACTED-PASSPORT]"),
    # Driver's license (US-style: 1 letter + 7-8 digits, or all-digit 8-9)
    (r"\b[A-Z]\d{7,8}\b", "[REDACTED-DL]"),
    # Financial account / routing numbers (8-17 digits standalone)
    (r"\b\d{8,17}\b", "[REDACTED-ACCOUNT]"),
]

_COMPILED_PII = [(re.compile(pattern), replacement) for pattern, replacement in _PII_PATTERNS]


def redact_pii(text: str) -> str:
    """Return *text* with zero-tolerance PII and secrets replaced by redaction tokens."""
    for compiled, replacement in _COMPILED_PII:
        text = compiled.sub(replacement, text)
    return text

# Ordered list of (compiled_pattern, replacement_label) for zero-tolerance PII.
_PII_PATTERNS: list[tuple[re.Pattern, str]] = [
    # Social Security Number  e.g. 123-45-6789 / 123 45 6789 / 123456789
    (re.compile(r"\b(?!000|666|9\d{2})\d{3}[\s\-]?(?!00)\d{2}[\s\-]?(?!0000)\d{4}\b"), "[SSN REDACTED]"),
    # Credit Card Number (13-19 digits, optionally separated by spaces/dashes)
    (re.compile(r"\b(?:\d[ \-]?){13,19}\b"), "[CREDIT_CARD REDACTED]"),
    # Email address
    (re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"), "[EMAIL REDACTED]"),
    # Phone number (various formats)
    (re.compile(r"\b(?:\+?1[\s.\-]?)?(?:\(?\d{3}\)?[\s.\-]?)\d{3}[\s.\-]?\d{4}\b"), "[PHONE REDACTED]"),
    # IPv4 address
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "[IP_ADDRESS REDACTED]"),
    # MAC address  e.g. 00:1A:2B:3C:4D:5E or 00-1A-2B-3C-4D-5E
    (re.compile(r"\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b"), "[MAC_ADDRESS REDACTED]"),
    # Passport number (letter(s) followed by 6-9 digits)
    (re.compile(r"\b[A-Z]{1,2}\d{6,9}\b"), "[PASSPORT REDACTED]"),
    # US Driver's License (common pattern: 1-2 letters + 5-8 digits)
    (re.compile(r"\b[A-Z]{1,2}\d{5,8}\b"), "[DL REDACTED]"),
    # Taxpayer Identification Number (same structure as SSN but broader label covered above)
    # Vehicle Identification Number (17 alphanumeric chars)
    (re.compile(r"\b[A-HJ-NPR-Z0-9]{17}\b"), "[VIN REDACTED]"),
    # Financial account numbers (8-17 consecutive digits not already caught)
    (re.compile(r"\b\d{8,17}\b"), "[ACCOUNT_NUMBER REDACTED]"),
]


def _redact_pii(text: str) -> str:
    """Return *text* with zero-tolerance PII categories replaced by redaction labels."""
    for pattern, label in _PII_PATTERNS:
        text = pattern.sub(label, text)
    return text

# Patterns that indicate dynamic code execution primitives that must never
# appear in LLM output that is acted upon by the application.
_DANGEROUS_PATTERNS = re.compile(
    r"""
    (?:^|\b)
    (?:
        eval\s*\(                          # Python/JS eval(...)
      | exec\s*\(                          # Python exec(...)
      | execfile\s*\(                      # Python 2 execfile
      | compile\s*\(                       # Python compile()
      | __import__\s*\(                    # Python __import__
      | importlib\.import_module\s*\(      # importlib dynamic import
      | subprocess\.(?:call|run|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True
                                           # subprocess with shell=True
      | os\.system\s*\(                    # os.system shell execution
      | os\.popen\s*\(                     # os.popen shell execution
      | commands\.getoutput\s*\(           # legacy commands module
      | (?:bash|sh|zsh|ksh)\s+-c\s+        # bash/sh -c ...
      | `[^`]+`                            # backtick shell execution
      | \$\([^)]+\)                        # $(...) shell substitution
    )
    """,
    re.VERBOSE | re.IGNORECASE | re.MULTILINE,
)


def sanitize_llm_output(text: str, agent_name: str = "unknown") -> str:
    """Remove lines that contain dynamic code-execution primitives from LLM output.

    Any line that matches a known dangerous pattern (eval, exec, subprocess
    with shell=True, bash -c, backtick expansion, etc.) is dropped and a
    warning is logged so that the removal is auditable.
    """
    lines = text.splitlines(keepends=True)
    clean_lines = []
    for line in lines:
        if _DANGEROUS_PATTERNS.search(line):
            logger.warning(
                "sanitize_llm_output: removed dangerous line from %s agent response: %r",
                agent_name,
                line.rstrip(),
            )
        else:
            clean_lines.append(line)
    return "".join(clean_lines)


class TicketState(TypedDict, total=False):
    ticket_text: str
    model_overrides: dict[str, str]
    category: str
    priority: str
    reply: str
    models_used: dict[str, str]
    provenance: dict  # signed provenance envelope for the AI-generated reply


def intake(state: TicketState) -> TicketState:
    ticket_text = state["ticket_text"].strip()

    # [AI_DAT_SEC_010] Log only the redacted version of the ticket text.
    logger.info("ticket intake text=%s", _redact_pii(ticket_text))

    return {"ticket_text": ticket_text, "models_used": {}}


def triage_agent(state: TicketState) -> TicketState:
    system = SystemMessage(
        "You are a support triage agent. Classify the ticket. Respond with JSON only: "
        f'{{"category": one of {TICKET_CATEGORIES}, "priority": one of {TICKET_PRIORITIES}}}'
    )
    # [AI_DAT_SEC_011] Redact PII/secrets before sending to the model.
    user = HumanMessage(redact_pii(state["ticket_text"]))

    logger.info(
        "llm_request agent=triage messages=%s",
        [{"role": m.type, "content": m.content} for m in [system, user]],
    )
    text, model_name = llm.invoke("triage", [system, user], state.get("model_overrides", {}).get("triage"))
    logger.info("llm_response agent=triage model=%s response=%s", model_name, text)
    text = sanitize_llm_output(text, agent_name="triage")
    try:
        parsed = json.loads(text.strip().removeprefix("```json").removesuffix("```"))
    except json.JSONDecodeError:
        logger.warning("triage returned non-JSON output; defaulting")
        parsed = {}

    return {
        "category": parsed.get("category", "other"),
        "priority": parsed.get("priority", "medium"),
        "models_used": {**state["models_used"], "triage": model_name},
    }


# ---------------------------------------------------------------------------
# Provenance helpers (inline, scoped to this module)
# ---------------------------------------------------------------------------
_PROVENANCE_SIGNING_KEY: bytes = os.environb.get(
    b"AI_PROVENANCE_SIGNING_KEY",
    b"change-me-in-production-32-bytes!",  # fallback for local dev only
)

_AI_CONTENT_LABEL = "[AI-GENERATED CONTENT]"


def _build_provenance_envelope(text: str, model_name: str, prompt_hash: str) -> dict:
    """Build a signed provenance envelope for an AI-generated reply.

    Raises RuntimeError if signing fails so callers can fail closed.
    """
    metadata = {
        "content_origin": "ai-generated",
        "model_id": model_name,
        "generation_timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "prompt_sha256": prompt_hash,
        "label": _AI_CONTENT_LABEL,
    }
    try:
        canonical = json.dumps(metadata, sort_keys=True, separators=(",", ":"}).encode()
        signature = hmac.new(_PROVENANCE_SIGNING_KEY, canonical, hashlib.sha256).hexdigest()
    except Exception as exc:  # pragma: no cover
        raise RuntimeError(
            "AI provenance signing failed — refusing to serve unlabeled content"
        ) from exc

    return {
        "provenance": {
            **metadata,
            "signature_hmac_sha256": signature,
        },
        "labeled_reply": f"{_AI_CONTENT_LABEL}\n{text}",
    }


def resolver_agent(state: TicketState) -> TicketState:
    system = SystemMessage(
        "You are a helpful customer support agent. Write a short, friendly reply to the "
        "customer that summarizes their issue and the next steps. "
        f"Ticket category: {state['category']}, priority: {state['priority']}."
    )
    # [AI_DAT_SEC_011] Do not send PII to AI Models — UNGUARDED: the raw ticket
    # including PII is sent to the model.
    user = HumanMessage(state["ticket_text"])

    text, model_name = llm.invoke("resolver", [system, user], state.get("model_overrides", {}).get("resolver"))

    # --- Provenance, labeling, and signing (fail-closed) -------------------
    prompt_hash = hashlib.sha256(
        (system.content + user.content).encode("utf-8", errors="replace")
    ).hexdigest()

    # Raises RuntimeError on failure → graph propagates the error and the
    # unlabeled reply is never stored in state or returned to the caller.
    envelope = _build_provenance_envelope(text, model_name, prompt_hash)

    return {
        "reply": envelope["labeled_reply"],
        "models_used": {
            **state["models_used"],
            "resolver": model_name,
        },
        "provenance": envelope["provenance"],
    }


def respond(state: TicketState) -> TicketState:
    logger.info(
        "ticket resolved category=%s priority=%s models=%s",
        state["category"], state["priority"], state["models_used"],
    )
    return {}


def build_graph():
    graph = StateGraph(TicketState)
    graph.add_node("intake", intake)
    graph.add_node("triage_agent", triage_agent)
    graph.add_node("resolver_agent", resolver_agent)
    graph.add_node("respond", respond)
    graph.add_edge(START, "intake")
    graph.add_edge("intake", "triage_agent")
    graph.add_edge("triage_agent", "resolver_agent")
    graph.add_edge("resolver_agent", "respond")
    graph.add_edge("respond", END)
    return graph.compile()


_GRAPH = None


def run_ticket(ticket_text: str, model_overrides: dict[str, str] | None = None) -> TicketState:
    global _GRAPH
    if _GRAPH is None:
        _GRAPH = build_graph()
    return _GRAPH.invoke({"ticket_text": ticket_text, "model_overrides": model_overrides or {}})
