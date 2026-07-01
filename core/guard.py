"""Optional guard-core perimeter for Odysseus.

This module wires the ``fastapi-guard`` / ``guard-core`` security engine in as an
opt-in outer perimeter (rate-limit ceilings, WAF/recon detection, honeypot
auto-ban, per-route size/content-type caps, and log-only signals for
credential-into-corpus and stored prompt-injection). It is disabled by default.

Design contract:
- When ``ODYSSEUS_GUARD_ENABLED`` is not ``true`` the guard packages are never
  imported, ``guard_deco`` stays ``None``, and every decorator in
  ``core.guard_deco`` degrades to a no-op. Odysseus then behaves byte-for-byte as
  if this module did not exist, and ``fastapi-guard`` need not be installed.
- Odysseus already owns security headers, CORS, auth, outbound SSRF validation,
  secret redaction, owner-scope, and upload size caps. The guard therefore
  disables its overlapping subsystems (headers/CORS) and augments the rest.
- The engine ships in ``passive_mode`` (log-only, never blocks) until an operator
  reviews the JSON logs and flips ``ODYSSEUS_GUARD_PASSIVE=false``. This matches
  Odysseus's existing stance of wrapping untrusted content rather than rejecting
  it (see ``src/prompt_security.py``).
"""

from __future__ import annotations

import os
import re

GUARD_ENABLED = os.getenv("ODYSSEUS_GUARD_ENABLED", "false").lower() == "true"


def _passive_mode() -> bool:
    return os.getenv("ODYSSEUS_GUARD_PASSIVE", "true").lower() != "false"


def _emergency_mode() -> bool:
    return os.getenv("ODYSSEUS_GUARD_EMERGENCY", "false").lower() == "true"


security_config = None
guard_deco = None
scan_credentials_validator = None
scan_injection_validator = None


if GUARD_ENABLED:
    from guard import SecurityConfig, SecurityDecorator
    from guard.adapters import StarletteResponseFactory
    from guard_core.models import BehaviorRuleConfig, ThreatBanConfig

    _factory = StarletteResponseFactory()

    # Credential formats that must never be written into the searchable/RAG
    # corpus. Applied ONLY to content-corpus routes (memory/notes/documents/
    # skills/import) — never to the key-config routes that legitimately carry
    # secrets (session, model-endpoints, embeddings, auth/integrations, v1/chat).
    _CREDENTIAL_PATTERNS = [
        re.compile(r"sk-ant-[a-zA-Z0-9\-_]{15,}"),
        re.compile(r"\bsk-[a-zA-Z0-9]{20,}\b"),
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
        re.compile(r"\bhf_[A-Za-z0-9]{20,}\b"),
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        re.compile(r"postgres(?:ql)?://[^:\s]+:[^@\s]{4,}@"),
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ]

    # Role-override / delimiter-injection phrasing. Flagged as a log signal on
    # stored-instruction surfaces (assistant persona, skill overrides, scheduled
    # task prompts). In passive_mode this only logs; it never rejects content.
    _INJECTION_PATTERNS = [
        re.compile(r"ignore\s+(?:all\s+)?(?:previous|above|prior)\s+(?:instructions?|prompts?)", re.I),
        re.compile(r"you\s+are\s+now\s+(?:a|an|the|DAN|developer\s+mode)", re.I),
        re.compile(r"disregard\s+(?:your|the)\s+(?:system\s+prompt|rules|guidelines)", re.I),
        re.compile(r"<\|(?:im_start|im_end|system|user|assistant)\|>", re.I),
        re.compile(r"\[INST\]|\[/INST\]|\[\[SYSTEM\]\]", re.I),
    ]

    async def _scan_credentials(request):
        try:
            raw = (await request.body()).decode("utf-8", "ignore")[:16384]
        except Exception:
            return None
        for pattern in _CREDENTIAL_PATTERNS:
            if pattern.search(raw):
                return _factory.create_response(
                    '{"error":"credential-like content rejected"}', 400
                )
        return None

    async def _scan_injection(request):
        try:
            raw = (await request.body()).decode("utf-8", "ignore")[:16384]
        except Exception:
            return None
        for pattern in _INJECTION_PATTERNS:
            if pattern.search(raw):
                return _factory.create_response(
                    '{"error":"prompt-injection pattern flagged"}', 400
                )
        return None

    scan_credentials_validator = _scan_credentials
    scan_injection_validator = _scan_injection

    security_config = SecurityConfig(
        trusted_proxies=[],
        trusted_proxy_depth=1,
        trust_x_forwarded_proto=False,
        enable_redis=False,
        passive_mode=_passive_mode(),
        fail_secure=True,
        enforce_https=False,
        exclude_paths=[
            "/api/health",
            "/api/version",
            "/api/auth/setup",
            "/api/auth/signup",
            "/api/auth/login",
            "/api/auth/logout",
            "/api/auth/status",
            "/api/auth/features",
            "/api/auth/settings",
            "/api/auth/integrations/presets",
            "/login",
            "/static",
            "/docs",
            "/redoc",
            "/openapi.json",
            "/favicon.ico",
        ],
        security_headers={"enabled": False},
        enable_cors=False,
        enable_rate_limiting=True,
        rate_limit=300,
        rate_limit_window=60,
        endpoint_rate_limits={
            "/api/shell/exec": (10, 60),
            "/api/shell/stream": (10, 60),
            "/api/mcp/servers": (10, 60),
            "/api/vault/unlock": (5, 60),
            "/api/vault/login": (5, 60),
            "/api/tokens": (10, 60),
            "/api/v1/chat": (30, 60),
            "/api/export": (5, 300),
            "/api/import": (5, 300),
        },
        enable_penetration_detection=True,
        excluded_detection_body_fields={
            "message", "content", "text", "prompt", "personality", "procedure",
            "pitfalls", "solution", "when_to_use", "description", "query",
            "payload", "thumbnail", "items", "instruction", "original_text",
            "body", "code", "diff",
        },
        excluded_detection_headers={
            "authorization", "x-api-key", "x-auth-token",
            "x-odysseus-internal-token", "x-odysseus-owner", "x-tz-offset",
        },
        detection_max_body_inspect_bytes=65536,
        detection_max_content_length=10000,
        detection_threat_score_threshold=1.2,
        detection_semantic_threshold=0.75,
        enable_ip_banning=True,
        auto_ban_threshold=20,
        auto_ban_duration=3600,
        threat_ban_config={
            "recon": ThreatBanConfig(threshold=5, duration=86400),
            "sensitive_file": ThreatBanConfig(threshold=3, duration=86400),
            "cms_probing": ThreatBanConfig(threshold=3, duration=86400),
        },
        global_behavior_rules=[
            BehaviorRuleConfig(
                rule_type="return_pattern", threshold=40, window=300,
                pattern="status:404", action="log", correlate_with_detection=True,
            ),
            BehaviorRuleConfig(
                rule_type="return_pattern", threshold=20, window=120,
                pattern="status:401", action="log", correlate_with_detection=True,
            ),
        ],
        log_format="json",
        log_suspicious_level="WARNING",
        log_request_level=None,
        emergency_mode=_emergency_mode(),
        emergency_whitelist=["127.0.0.1", "::1"],
        enable_agent=False,
    )

    guard_deco = SecurityDecorator(security_config)
