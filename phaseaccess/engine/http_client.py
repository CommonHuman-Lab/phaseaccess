# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab

"""
PhaseAccess — engine/http_client.py
Shared HTTP opener factory with caching.

Both fingerprint.py and tamper.py previously rebuilt the urllib opener
(including ssl.create_default_context()) on every single request.  This
module centralises opener construction and caches an opener per
(proxy, verify_ssl) combination so the SSL context is only created once.

Standalone-safe: stdlib only.
"""

from __future__ import annotations

import ssl
import threading
import urllib.request as _req
from typing import Dict, Tuple

# Module-level cache: (proxy, verify_ssl) → opener
_opener_cache: Dict[Tuple[str, bool], _req.OpenerDirector] = {}
_opener_lock = threading.Lock()


def get_opener(proxy: str, verify_ssl: bool) -> _req.OpenerDirector:
    """
    Return a cached urllib OpenerDirector for the given (proxy, verify_ssl)
    configuration.  The opener — including the SSL context — is created once
    and reused across all requests with the same settings.
    """
    key = (proxy, verify_ssl)
    opener = _opener_cache.get(key)
    if opener is not None:
        return opener

    with _opener_lock:
        # Double-checked locking
        opener = _opener_cache.get(key)
        if opener is not None:
            return opener

        handler_chain: list = []
        if proxy:
            handler_chain.append(_req.ProxyHandler({'http': proxy, 'https': proxy}))
        if not verify_ssl:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
            handler_chain.append(_req.HTTPSHandler(context=ssl_ctx))
        handler_chain.append(_req.HTTPCookieProcessor())

        opener = _req.build_opener(*handler_chain)
        _opener_cache[key] = opener

    return opener


def clear_opener_cache() -> None:
    """Flush the opener cache.  Useful in tests or after config changes."""
    with _opener_lock:
        _opener_cache.clear()
