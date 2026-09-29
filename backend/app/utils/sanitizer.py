"""
CloudScope Centralized Secret Masking & Sanitization Utility.

Prevents credential leakage into logs, audit entries, metrics, and Copilot AI context.
Masks AWS Access Keys, Secret Keys, Session Tokens, Gemini API Keys, and Private Keys.
"""

import re
from typing import Any, Dict, List, Union

REDACTED_STR = "[REDACTED]"

# Regex patterns matching common secret formats
PATTERNS = [
    # AWS Access Key ID (e.g. AKIAIOSFODNN7EXAMPLE, ASIA...)
    (re.compile(r"\b(AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"), r"\1****************"),
    # AWS Secret Access Key (approx 40 chars base64)
    (re.compile(r"(?i)(aws_secret_access_key|secret_key|secretaccesskey)[\s:=]+['\"]?([A-Za-z0-9/+=]{40})['\"]?"), r"\1=[REDACTED]"),
    # AWS Session Token (typically 100+ chars)
    (re.compile(r"(?i)(aws_session_token|session_token)[\s:=]+['\"]?([A-Za-z0-9/+=]{50,})['\"]?"), r"\1=[REDACTED]"),
    # Google / Gemini API Key (AIza...)
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{30,40}\b"), "[REDACTED_GEMINI_KEY]"),
    # Generic Private Key blocks
    (re.compile(r"-----BEGIN[ A-Z0-9_-]+PRIVATE KEY-----[\s\S]*?-----END[ A-Z0-9_-]+PRIVATE KEY-----"), "[REDACTED_PRIVATE_KEY]"),
    # Authorization Bearer tokens
    (re.compile(r"(?i)bearer\s+[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+"), "Bearer [REDACTED_JWT]"),
    # Password key-values in query strings or JSON
    (re.compile(r"(?i)(password|secret|passwd|token|api_?key)[\s:=]+['\"]?([^\s,;'\"]+)['\"]?"), r"\1=[REDACTED]"),
]


def sanitize_text(text: str) -> str:
    """Mask credentials and sensitive tokens within plain text."""
    if not isinstance(text, str):
        return str(text)
    sanitized = text
    for pattern, replacement in PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized


def sanitize_data(data: Any) -> Any:
    """Recursively sanitize dicts, lists, and strings for safe logging or storage."""
    if isinstance(data, dict):
        cleaned: Dict[str, Any] = {}
        for k, v in data.items():
            k_lower = str(k).lower()
            if any(s in k_lower for s in ("password", "secret", "private_key", "token", "credential", "auth_key", "api_key", "apikey", "access_key")):
                cleaned[k] = REDACTED_STR
            else:
                cleaned[k] = sanitize_data(v)
        return cleaned
    elif isinstance(data, (list, tuple, set)):
        return [sanitize_data(item) for item in data]
    elif isinstance(data, str):
        return sanitize_text(data)
    else:
        return data
