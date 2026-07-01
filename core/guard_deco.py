"""No-op-safe decorator shim over the guard-core perimeter.

Route modules import decorators from here, so the same call site works whether or
not the perimeter is enabled: when ``ODYSSEUS_GUARD_ENABLED`` is off,
``core.guard.guard_deco`` is ``None`` and every symbol below returns the
undecorated function unchanged.

These per-route decorators require fastapi-guard >= 7.2.2, whose route resolver
descends into include_router wrappers; on older versions they silently no-op on
Odysseus's routes (all registered via include_router). The broad perimeter lives
in the global config (core/guard.py) regardless; these decorators add tighter,
per-surface controls on top.
"""

from __future__ import annotations

from typing import Any

from core.guard import guard_deco as _gd


def _noop(*_a: Any, **_kw: Any):
    def deco(fn: Any) -> Any:
        return fn

    return deco


rate_limit = (lambda requests, window=60: _gd.rate_limit(requests, window)) if _gd else _noop
max_size = (lambda size_bytes: _gd.max_request_size(size_bytes)) if _gd else _noop
content_type = (lambda allowed: _gd.content_type_filter(allowed)) if _gd else _noop
no_waf = (lambda: _gd.suspicious_detection(False)) if _gd else _noop
detection_ex = (lambda **kw: _gd.detection_exclusion(**kw)) if _gd else _noop
usage_monitor = (lambda calls, window=3600, action="log": _gd.usage_monitor(calls, window, action)) if _gd else _noop
suspicious_frequency = (lambda freq, window=300, action="log": _gd.suspicious_frequency(freq, window, action)) if _gd else _noop
honeypot = (lambda fields: _gd.honeypot_detection(fields)) if _gd else _noop
