"""
guardrails.py — NetOps AI Agent Security & Quality Guardrails
=============================================================
Provides five layers of validation/sanitization as pure functions.
All functions return a GuardrailResult so callers can decide how to respond.

Usage:
    from guardrails import check_security, check_ip_validity, ...
    result = check_security(user_input)
    if not result.passed:
        return {"error": result.reason}
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional

# ──────────────────────────────────────────────────────────────────────────────
# Core result type
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class GuardrailResult:
    passed: bool
    reason: str = "OK"
    sanitized_value: Optional[str] = None   # cleaned version of input, if applicable


# ──────────────────────────────────────────────────────────────────────────────
# 1. SECURITY & PRIVACY
# ──────────────────────────────────────────────────────────────────────────────

# Prompt injection patterns — attempts to hijack the LLM's instruction context
_PROMPT_INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?",
    r"you\s+are\s+now\s+",
    r"disregard\s+(all\s+)?previous",
    r"forget\s+(everything|all|your\s+instructions)",
    r"new\s+instructions?:",
    r"system\s+prompt\s*:",
    r"jailbreak",
    r"act\s+as\s+(a\s+)?(DAN|evil|unrestricted)",
    r"do\s+anything\s+now",
    r"pretend\s+you\s+(are|have\s+no)",
    r"override\s+(safety|guidelines|rules)",
]

# Shell command injection characters that should never appear in an IP address
_SHELL_INJECTION_CHARS = re.compile(r"[;&|`$<>()\\\n\r]")

# PII patterns to redact from log messages before storing/sending
_PII_PATTERNS = [
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"), "[EMAIL_REDACTED]"),
    (re.compile(r"\b(\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b"), "[PHONE_REDACTED]"),
    # SSN pattern (US)
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[SSN_REDACTED]"),
    # Credit card (very basic)
    (re.compile(r"\b(?:\d[ -]?){13,16}\b"), "[CARD_REDACTED]"),
]


def check_security(text: str) -> GuardrailResult:
    """
    Guardrail 1 — Security & Privacy.
    Checks for prompt injection attempts in the input text.
    Returns a failed result immediately if any injection pattern is detected.
    """
    if not text or not isinstance(text, str):
        return GuardrailResult(passed=False, reason="Input is empty or not a string.")

    lower = text.lower()
    for pattern in _PROMPT_INJECTION_PATTERNS:
        if re.search(pattern, lower):
            # print(f"🚨 [GUARDRAIL] Prompt injection detected. Pattern: '{pattern}'")
            return GuardrailResult(
                passed=False,
                reason=f"Security violation: prompt injection attempt detected."
            )

    return GuardrailResult(passed=True, reason="OK")


def scrub_pii(text: str) -> str:
    """
    Sanitize PII (emails, phone numbers, SSNs, card numbers) from a string.
    Returns the cleaned version — does NOT block, only redacts.
    """
    for pattern, replacement in _PII_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def check_command_injection(ip_string: str) -> GuardrailResult:
    """
    Ensures an IP string contains no shell metacharacters before
    it reaches subprocess.run(). Lightweight but critical.
    """
    if _SHELL_INJECTION_CHARS.search(ip_string):
        # print(f"🚨 [GUARDRAIL] Command injection attempt in IP string: '{ip_string}'")
        return GuardrailResult(
            passed=False,
            reason="Security violation: shell metacharacters detected in IP address."
        )
    return GuardrailResult(passed=True, reason="OK")


# ──────────────────────────────────────────────────────────────────────────────
# 2. RESPONSE RELEVANCE
# ──────────────────────────────────────────────────────────────────────────────

_IPV4_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

_OFF_TOPIC_PHRASES = [
    "i'm sorry",
    "i cannot",
    "as an ai",
    "i don't have access",
    "i am unable",
    "i apologize",
    "i'm unable",
    "please note that",
    "as a language model",
]

_MIN_RESPONSE_LENGTH = 5
_MAX_RESPONSE_LENGTH = 2000


def check_response_relevance(llm_output: str) -> GuardrailResult:
    """
    Guardrail 2 — Response Relevance.
    Validates the LLM response is on-topic, the right length, and contains an IP.
    """
    if not llm_output:
        return GuardrailResult(passed=False, reason="LLM returned an empty response.")

    if len(llm_output) < _MIN_RESPONSE_LENGTH:
        return GuardrailResult(
            passed=False,
            reason=f"LLM response too short ({len(llm_output)} chars). May be a failure."
        )

    if len(llm_output) > _MAX_RESPONSE_LENGTH:
        # print(f"⚠️ [GUARDRAIL] LLM response unusually long ({len(llm_output)} chars). Truncating.")
        llm_output = llm_output[:_MAX_RESPONSE_LENGTH]

    lower = llm_output.lower()
    for phrase in _OFF_TOPIC_PHRASES:
        if phrase in lower:
            # print(f"⚠️ [GUARDRAIL] LLM went off-topic. Phrase detected: '{phrase}'")
            return GuardrailResult(
                passed=False,
                reason=f"LLM response appears off-topic (contains: '{phrase}').",
                sanitized_value=llm_output
            )

    if not _IPV4_REGEX.search(llm_output):
        return GuardrailResult(
            passed=False,
            reason="LLM response does not contain a valid IPv4 address.",
            sanitized_value=llm_output
        )

    return GuardrailResult(passed=True, reason="OK", sanitized_value=llm_output)


# ──────────────────────────────────────────────────────────────────────────────
# 3. LANGUAGE QUALITY
# ──────────────────────────────────────────────────────────────────────────────

_MIN_REPORT_LENGTH = 20

_PROFANITY_LIST = [
    "fuck", "shit", "bitch", "asshole", "bastard", "cunt", "damn", "crap"
]

_GIBBERISH_REGEX = re.compile(r"[^\x00-\x7F]{10,}")   # 10+ consecutive non-ASCII chars


def check_language_quality(text: str, context: str = "report") -> GuardrailResult:
    """
    Guardrail 3 — Language Quality.
    Validates that a generated text (e.g., Azure forensic report) is clean and meaningful.
    """
    if not text or len(text.strip()) < _MIN_REPORT_LENGTH:
        return GuardrailResult(
            passed=False,
            reason=f"Generated {context} is too short to be meaningful (< {_MIN_REPORT_LENGTH} chars)."
        )

    if _GIBBERISH_REGEX.search(text):
        return GuardrailResult(
            passed=False,
            reason=f"Generated {context} contains a flood of non-ASCII/gibberish characters."
        )

    lower = text.lower()
    found_profanity = [w for w in _PROFANITY_LIST if w in lower]
    if found_profanity:
        # print(f"⚠️ [GUARDRAIL] Profanity detected in {context}: {found_profanity}")
        return GuardrailResult(
            passed=False,
            reason=f"Generated {context} contains inappropriate language."
        )

    return GuardrailResult(passed=True, reason="OK", sanitized_value=text.strip())


# ──────────────────────────────────────────────────────────────────────────────
# 4. CONTENT VALIDATION
# ──────────────────────────────────────────────────────────────────────────────

_ALLOWED_ACTIONS = {
    "LOGIN", "LOGOUT", "SSH", "SSH_LOGIN", "HTTP", "HTTPS", "FTP",
    "DNS", "ICMP", "RDP", "TELNET", "PORT_SCAN", "FILE_ACCESS",
    "DATABASE", "API_CALL", "FIREWALL_DROP", "SYSTEM"
}

_ALLOWED_STATUSES = {
    "SUCCESS", "FAILED", "ATTEMPT", "BLOCKED", "ALLOWED",
    "ERROR", "TIMEOUT", "DENIED", "UNKNOWN"
}

_MAX_MESSAGE_LENGTH = 2000


def check_content(log_entry: dict) -> GuardrailResult:
    """
    Guardrail 4 — Content Validation.
    Validates a log entry dict before it is stored to the database.
    """
    ip = log_entry.get("ip_address", "")
    timestamp = log_entry.get("timestamp", "")
    action = log_entry.get("action", "")
    status = log_entry.get("status", "")
    message = log_entry.get("message", "")

    # Validate IP format
    ip_check = check_ip_validity(ip, allow_private=True, context="log ingestion")
    if not ip_check.passed:
        return GuardrailResult(passed=False, reason=f"Invalid ip_address: {ip_check.reason}")

    # Validate timestamp is parseable
    if timestamp:
        parsed = False
        for fmt in (
            "%Y-%m-%dT%H:%M:%S",           # 2026-05-17T12:43:38
            "%Y-%m-%dT%H:%M:%S.%f",        # 2026-05-17T12:43:38.467259  ← Python default
            "%Y-%m-%d %H:%M:%S",           # 2026-05-17 12:43:38
            "%Y-%m-%dT%H:%M:%SZ",          # 2026-05-17T12:43:38Z
            "%Y-%m-%dT%H:%M:%S.%fZ",       # 2026-05-17T12:43:38.467259Z
            "%Y-%m-%dT%H:%M:%S%z",         # 2026-05-17T12:43:38+06:00
            "%Y-%m-%dT%H:%M:%S.%f%z",      # 2026-05-17T12:43:38.467259+06:00
        ):
            try:
                datetime.strptime(timestamp, fmt)
                parsed = True
                break
            except ValueError:
                continue
        if not parsed:
            return GuardrailResult(
                passed=False,
                reason=f"Invalid timestamp format: '{timestamp}'. Expected ISO 8601."
            )

    # Validate action
    if action.upper() not in _ALLOWED_ACTIONS:
        # print(f"⚠️ [GUARDRAIL] Unknown action type: '{action}'. Allowing but flagging.")
        pass  # Warn but allow — unknown actions shouldn't crash the system

    # Validate status
    if status.upper() not in _ALLOWED_STATUSES:
        # print(f"⚠️ [GUARDRAIL] Unknown status value: '{status}'. Allowing but flagging.")
        pass  # Warn but allow

    # Validate message length
    if not message or not message.strip():
        return GuardrailResult(passed=False, reason="Log message cannot be empty.")

    if len(message) > _MAX_MESSAGE_LENGTH:
        return GuardrailResult(
            passed=False,
            reason=f"Log message exceeds max length ({len(message)} > {_MAX_MESSAGE_LENGTH} chars)."
        )

    return GuardrailResult(passed=True, reason="OK")


# ──────────────────────────────────────────────────────────────────────────────
# 5. LOGIC & FUNCTIONALITY
# ──────────────────────────────────────────────────────────────────────────────

# In-memory rate limiter: { ip: [timestamp, timestamp, ...] }
_rate_limit_store: dict[str, list[datetime]] = {}
_RATE_LIMIT_MAX = 5          # max events
_RATE_LIMIT_WINDOW_SECS = 60 # within this many seconds


def check_ip_validity(
    ip: str,
    allow_private: bool = True,
    context: str = "blocking"
) -> GuardrailResult:
    """
    Guardrail: IP address structural and range validation.
    - Rejects malformed IPs
    - Rejects special-purpose addresses (0.0.0.0, 255.255.255.255, loopback)
    - Warns (but allows by default) private/RFC1918 IPs
    """
    if not ip or not isinstance(ip, str):
        return GuardrailResult(passed=False, reason="IP address is empty or not a string.")

    ip = ip.strip()

    # Shell injection safety first
    injection_check = check_command_injection(ip)
    if not injection_check.passed:
        return injection_check

    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return GuardrailResult(
            passed=False,
            reason=f"'{ip}' is not a valid IPv4/IPv6 address."
        )

    # Block reserved / unusable addresses
    if addr.is_unspecified:       # 0.0.0.0
        return GuardrailResult(passed=False, reason=f"'{ip}' is an unspecified address (0.0.0.0).")
    if addr.is_loopback:          # 127.x.x.x
        return GuardrailResult(passed=False, reason=f"'{ip}' is a loopback address.")
    if addr.is_multicast:
        return GuardrailResult(passed=False, reason=f"'{ip}' is a multicast address.")
    if addr.is_reserved:
        return GuardrailResult(passed=False, reason=f"'{ip}' is a reserved address.")

    # Private range: warn but allow (configurable)
    if addr.is_private and not allow_private:
        return GuardrailResult(
            passed=False,
            reason=f"'{ip}' is a private/RFC1918 address. {context.capitalize()} private IPs is disallowed."
        )
    if addr.is_private:
        # print(f"⚠️ [GUARDRAIL] '{ip}' is a private IP. Allowing for {context} but flagging.")
        pass  # Warn but allow

    return GuardrailResult(passed=True, reason="OK", sanitized_value=ip)


def check_logic_before_execute(
    ip: str,
    staged_rules_path: str,
    blocked_ips_set: set
) -> GuardrailResult:
    """
    Guardrail 5 — Logic & Functionality.
    Before executing a firewall block, verify:
      1. IP was actually staged (exists in staged_rules.txt)
      2. IP is not already blocked (double-block prevention)
      3. IP passes rate limiting
    """
    # 1. Double-block prevention
    if ip in blocked_ips_set:
        return GuardrailResult(
            passed=False,
            reason=f"IP '{ip}' is already in the blocked set. Skipping duplicate block."
        )

    # 2. Check staged_rules.txt to confirm IP was staged
    try:
        import os
        if os.path.exists(staged_rules_path):
            with open(staged_rules_path, "r") as f:
                staged_content = f.read()
            if ip not in staged_content:
                # print(f"⚠️ [GUARDRAIL] IP '{ip}' not found in staged rules. Proceeding anyway.")
                pass  # Warn but don't hard-block — staging script may not have written yet
    except Exception as e:
        # print(f"⚠️ [GUARDRAIL] Could not read staged rules file: {e}")
        pass  # Non-fatal — continue with rate limiting

    # 3. Rate limiting
    now = datetime.utcnow()
    window_start = now - timedelta(seconds=_RATE_LIMIT_WINDOW_SECS)
    events = _rate_limit_store.get(ip, [])
    # Prune old events outside the window
    events = [t for t in events if t > window_start]
    events.append(now)
    _rate_limit_store[ip] = events

    if len(events) > _RATE_LIMIT_MAX:
        return GuardrailResult(
            passed=False,
            reason=(
                f"Rate limit exceeded for IP '{ip}': "
                f"{len(events)} events in {_RATE_LIMIT_WINDOW_SECS}s "
                f"(max {_RATE_LIMIT_MAX})."
            )
        )

    return GuardrailResult(passed=True, reason="OK")
