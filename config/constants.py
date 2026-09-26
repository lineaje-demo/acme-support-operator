"""Constants for the Acme Support Ticket Operator.

Policy IDs below map to the UnifAI policies tested in Confluence:
"UnifAI Stubs and Guardrails - Sept 2026" -> Test Cases - 22nd Sept 2026.
"""

import re
from pathlib import Path

# --- UnifAI policy IDs (referenced in code comments as [POLICY_ID]) ---------
POLICY_APPROVED_LLMS = "AI_APP_SEC_006"     # Use only LLMs from the organization's approved list
POLICY_DISALLOWED_LLMS = "AI_APP_SEC_028"   # Do not use LLMs from the organization's disallowed list
POLICY_NO_PII_IN_LOGS = "AI_DAT_SEC_010"    # Do not log PII
POLICY_NO_PII_TO_MODELS = "AI_DAT_SEC_011"  # Do not send PII to AI Models
POLICY_MASK_PII_ON_UI = "AI_DAT_SEC_012"    # Mask PII on user interfaces

# --- OpenRouter / models ----------------------------------------------------
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"

# Default model per agent; overridable via env (TRIAGE_MODEL / RESOLVER_MODEL)
# and via the Streamlit sidebar.
DEFAULT_MODELS = {
    "triage": "meta-llama/llama-4-scout",
    "resolver": "meta-llama/llama-4-scout",
}

# --- Ticket handling --------------------------------------------------------
TICKET_CATEGORIES = ["billing", "account", "technical", "other"]
TICKET_PRIORITIES = ["low", "medium", "high"]

SAMPLE_TICKET = (
    "Hi, I'm REDACTED from REDACTED (SSN REDACTED, "
    "REDACTED, REDACTED). I was charged twice for my "
    "subscription this month on card REDACTED. Please help me get a refund."
). I was charged twice for my "
    "subscription this month on card [CREDIT CARD REDACTED]. Please help me get a refund."
)

# ---------------------------------------------------------------------------
# PII redaction utility  [AI_DAT_SEC_010 / AI_DAT_SEC_011 / AI_DAT_SEC_012]
# ---------------------------------------------------------------------------
# Zero-tolerance PII categories that must be redacted from any uploaded file
# before the content is stored, logged, or forwarded to an AI model.

_PII_PATTERNS: list[tuple[str, str]] = [
    # Social Security Number  (SSN)
    (r'\b(?!000|666|9\d{2})\d{3}[\s\-](?!00)\d{2}[\s\-](?!0000)\d{4}\b', '[SSN REDACTED]'),
    # Taxpayer Identification Number (same format as SSN but broader catch)
    (r'\b\d{2}-\d{7}\b', '[TIN REDACTED]'),
    # Credit Card Number (Visa, MC, Amex, Discover – with or without spaces/dashes)
    (r'\b(?:4[0-9]{3}|5[1-5][0-9]{2}|3[47][0-9]{2}|6(?:011|5[0-9]{2}))'  # issuer prefix
     r'(?:[\s\-]?[0-9]{4}){2,3}(?:[\s\-]?[0-9]{3,4})?\b', '[CREDIT CARD REDACTED]'),
    # Financial Account Number (generic 8-17 digit standalone number)
    (r'\b(?:account\s*(?:number|#|no\.?)?\s*:?\s*)[0-9]{8,17}\b', '[FINANCIAL ACCOUNT REDACTED]'),
    # Passport Number (letter(s) + 6-9 digits)
    (r'\b[A-Z]{1,2}[0-9]{6,9}\b', '[PASSPORT REDACTED]'),
    # Driver\'s License (common US formats: 1-2 letters + 5-8 digits)
    (r"(?i)\b(?:driver'?s?\s+licen[sc]e\s*(?:number|#|no\.?)?\s*:?\s*)[A-Z0-9]{5,12}\b",
     '[DRIVERS LICENSE REDACTED]'),
    # Vehicle Identification Number (VIN) – exactly 17 alphanumeric chars
    (r'\b[A-HJ-NPR-Z0-9]{17}\b', '[VIN REDACTED]'),
    # IP Address (IPv4)
    (r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b',
     '[IP ADDRESS REDACTED]'),
    # MAC Address
    (r'\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b', '[MAC ADDRESS REDACTED]'),
    # Email address
    (r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b', '[EMAIL REDACTED]'),
    # Personal Phone Number (US/international formats)
    (r'\b(?:\+?1[\s.\-]?)?(?:\(?[2-9][0-9]{2}\)?[\s.\-]?)[2-9][0-9]{2}[\s.\-]?[0-9]{4}\b',
     '[PHONE REDACTED]'),
    # Year of Birth (standalone 4-digit year 1900-2009 preceded by birth-related keyword)
    (r'(?i)\b(?:born|birth\s*year|year\s*of\s*birth|dob|date\s*of\s*birth)\s*:?\s*(19|20)\d{2}\b',
     '[YEAR OF BIRTH REDACTED]'),
    # Employee ID / School ID
    (r'(?i)\b(?:employee|emp|school|student)\s*(?:id|#|no\.?)\s*:?\s*[A-Z0-9]{4,12}\b',
     '[ID REDACTED]'),
]

# Compile once for performance
_COMPILED_PII_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(pattern, re.IGNORECASE), replacement)
    for pattern, replacement in _PII_PATTERNS
]


def redact_pii(text: str) -> str:
    """Scan *text* for zero-tolerance PII and return a redacted copy.

    This function MUST be called on the contents of every uploaded file
    before the content is:
      - forwarded to an AI model          [AI_DAT_SEC_011]
      - written to any log                [AI_DAT_SEC_010]
      - rendered on a user interface      [AI_DAT_SEC_012]

    Args:
        text: Raw string content (e.g. the decoded body of an uploaded file).

    Returns:
        A new string with all detected PII replaced by labelled placeholders.
        The original string is never mutated.
    """
    redacted = text
    for compiled_pattern, replacement in _COMPILED_PII_PATTERNS:
        redacted = compiled_pattern.sub(replacement, redacted)
    return redacted

# --- Paths ------------------------------------------------------------------
ROOT_DIR = Path(__file__).resolve().parents[1]
LOG_DIR = ROOT_DIR / "logs"
LLM_IO_LOG_FILE = LOG_DIR / "llm_io.jsonl"
