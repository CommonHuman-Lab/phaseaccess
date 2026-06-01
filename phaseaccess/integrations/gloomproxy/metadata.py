# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
from gloomproxy_sdk import PluginCapabilities

CAPABILITIES: PluginCapabilities = {
    "name": "phaseaccess",
    "modes": ["active"],
    "protocols": ["http", "https"],
    "auth_required": True,  # needs at least one session to test access control
    "distributed_safe": True,
    "vuln_types": ["idor", "bola", "broken_access_control"],
    "proxy_aware": True,
    "min_timeout": 30,
}
