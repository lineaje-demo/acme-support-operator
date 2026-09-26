"""OpenRouter model access for the support agents (via langchain-openai)."""

import hashlib
import hmac
import json
import logging
import os
from datetime import datetime, timezone

from langchain_core.messages import BaseMessage
from langchain_openai import ChatOpenAI

from config.constants import DEFAULT_MODELS, LLM_IO_LOG_FILE, OPENROUTER_BASE_URL

logger = logging.getLogger(__name__)


def resolve_model_name(agent: str, override: str | None = None) -> str:
    """Model for an agent: UI override, then env (<AGENT>_MODEL), then default."""
    return (
        (override or "").strip()
        or os.getenv(f"{agent.upper()}_MODEL", "").strip()
        or DEFAULT_MODELS[agent]
    )


def get_model(agent: str, override: str | None = None) -> ChatOpenAI:
    model_name = resolve_model_name(agent, override)

    # [AI_APP_SEC_006] Use only LLMs from the organization's approved list — UNGUARDED:
    # [AI_APP_SEC_028] Do not use LLMs from the organization's disallowed list — UNGUARDED:
    # any model name from env or the UI sidebar is used as-is, with no allow/deny check.
    logger.info("llm_call agent=%s model=%s", agent, model_name)
    return ChatOpenAI(
        model=model_name,
        base_url=OPENROUTER_BASE_URL,
        api_key=os.getenv("OPENROUTER_API_KEY"),
        temperature=0.2,
        max_tokens=400,
    )


# Patterns that indicate dynamic code execution primitives in LLM output.
_DANGEROUS_PATTERNS = [
    r"\beval\s*\(",                        # Python/JS eval(...)
    r"\bexec\s*\(",                        # Python exec(...)
    r"\bexecfile\s*\(",                    # Python 2 execfile(...)
    r"\bcompile\s*\(",                     # Python compile(...)
    r"\b__import__\s*\(",                  # Python __import__(...)
    r"\bimportlib\.import_module\s*\(",    # importlib dynamic import
    r"subprocess\.(?:call|run|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True",  # subprocess shell=True
    r"\bos\.system\s*\(",                  # os.system(...)
    r"\bos\.popen\s*\(",                   # os.popen(...)
    r"\bos\.execv[pe]?\s*\(",              # os.execv/execve/execvp
    r"\bcommands\.getoutput\s*\(",         # legacy commands module
    r"\bgetattr\s*\(.*,\s*['\"]__",        # getattr dunder access
    r"\bsetattr\s*\(",                     # setattr(...)
    r"\bdelattr\s*\(",                     # delattr(...)
    r"\bcreateFunction\s*\(",              # JS new Function(...)
    r"\bnew\s+Function\s*\(",              # JS new Function(...)
    r"\bsetTimeout\s*\(\s*['\"`]",         # JS setTimeout with string
    r"\bsetInterval\s*\(\s*['\"`]",        # JS setInterval with string
    r"\bdocument\.write\s*\(",             # JS document.write
    r"\binnerHTML\s*=",                    # JS innerHTML assignment
    r"\beval\s+['\"`$]",                   # bash eval 'cmd' / eval "cmd" / eval $var
    r"\bsource\s+",                        # bash source script
    r"\$\(.*\)",                           # bash command substitution $(...)
    r"`[^`]+`",                            # bash backtick command substitution
]

import re as _re

_COMPILED_PATTERNS = [_re.compile(p, _re.IGNORECASE) for p in _DANGEROUS_PATTERNS]


def sanitize_llm_output(text: str) -> str:
    """Remove lines containing dynamic code execution primitives from LLM output."""
    if not text:
        return text
    sanitized_lines = []
    for line in text.splitlines():
        matched_pattern = None
        for pattern in _COMPILED_PATTERNS:
            if pattern.search(line):
                matched_pattern = pattern.pattern
                break
        if matched_pattern:
            logger.warning(
                "llm_output_sanitized: removed line matching pattern=%r line=%r",
                matched_pattern,
                line,
            )
        else:
            sanitized_lines.append(line)
    return "\n".join(sanitized_lines)


def invoke(agent: str, messages: list[BaseMessage], override: str | None = None) -> tuple[str, str]:
    """Call the agent's model; returns (response_text, model_name)."""
    model = get_model(agent, override)
    response = model.invoke(messages)
    sanitized_content = sanitize_llm_output(response.content)
    _log_io(agent, model.model_name, messages, sanitized_content)
    return sanitized_content, model.model_name


def _log_io(agent: str, model_name: str, messages: list[BaseMessage], output: str) -> None:
    # TEST AID for [AI_DAT_SEC_011]: when LLM_IO_LOG=true, record exactly what was sent
    # to / received from OpenRouter, so testers can verify whether PII reached the model.
    # This file contains PII by design — do not enable outside testing.
    if os.getenv("LLM_IO_LOG", "").lower() != "true":
        return
    LLM_IO_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "agent": agent,
        "model": model_name,
        "input": [{"role": m.type, "content": m.content} for m in messages],
        "output": output,
    }
    with LLM_IO_LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")
