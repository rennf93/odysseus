"""No-op-safe decorator shim over the guard-core perimeter.

Route modules import decorators from here rather than from ``core.guard``
directly, so the same ``@rate_limit(...)`` / ``@scan_creds()`` call site works
whether or not the perimeter is enabled. When ``ODYSSEUS_GUARD_ENABLED`` is off,
``core.guard.guard_deco`` is ``None`` and every symbol below is a no-op that
returns the undecorated function unchanged.
"""

from __future__ import annotations

from typing import Any

from core.guard import guard_deco as _gd
from core.guard import scan_credentials_validator as _cred
from core.guard import scan_injection_validator as _inj


def _noop(*_a: Any, **_kw: Any):
    def deco(fn: Any) -> Any:
        return fn

    return deco


rate_limit = (lambda requests, window=60: _gd.rate_limit(requests, window)) if _gd else _noop
max_size = (lambda size_bytes: _gd.max_request_size(size_bytes)) if _gd else _noop
content_type = (lambda allowed: _gd.content_type_filter(allowed)) if _gd else _noop
usage_monitor = (lambda calls, window=3600, action="log": _gd.usage_monitor(calls, window, action)) if _gd else _noop
detection_ex = (lambda **kw: _gd.detection_exclusion(**kw)) if _gd else _noop
no_waf = (lambda: _gd.suspicious_detection(False)) if _gd else _noop
honeypot = (lambda fields: _gd.honeypot_detection(fields)) if _gd else _noop
require_ip = (lambda **kw: _gd.require_ip(**kw)) if _gd else _noop
scan_creds = (lambda: _gd.custom_validation(_cred)) if _gd else _noop
scan_inject = (lambda: _gd.custom_validation(_inj)) if _gd else _noop
