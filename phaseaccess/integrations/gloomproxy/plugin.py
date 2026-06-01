# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""GloomProxy plugin wrapper for PhaseAccess.

Thin adapter only — all IDOR detection logic lives in phaseaccess.engine.
"""
from __future__ import annotations

import asyncio
import logging

from gloomproxy_sdk import BaseScanner, Finding, ScanContext, Target, ScanOptionDef
from gloomproxy_sdk.capabilities import PluginCapabilities
from gloomproxy_sdk.manifest import PluginManifest, TrustLevel

from .adapter import build_options
from .mapper import map_results
from .metadata import CAPABILITIES

log = logging.getLogger(__name__)


class PhaseAccessPlugin(BaseScanner):
    name = "phaseaccess"
    version = "0.1.1"
    description = "Native IDOR and broken object-level authorization detection engine"
    author = "CommonHuman-Lab"
    tags = ["idor", "bola", "access-control", "active", "http"]

    @classmethod
    def capabilities(cls) -> PluginCapabilities:
        return CAPABILITIES

    @classmethod
    def manifest(cls) -> PluginManifest:
        return {
            "trust_level": TrustLevel.CORE,
            "resources": {"max_runtime": 600, "max_findings": 5000},
            "sdk_min_version": "0.1.0",
        }

    @classmethod
    def option_schema(cls) -> list[ScanOptionDef]:
        return [
            {"key": "crawl",     "label": "Crawl",     "type": "bool", "default": False, "description": "Crawl to discover IDOR-testable endpoints"},
            {"key": "threads",   "label": "Threads",   "type": "int",  "default": 5,    "description": "Concurrent request threads", "min": 1, "max": 20},
            {"key": "max_pages", "label": "Max pages", "type": "int",  "default": 50,   "description": "Maximum pages to crawl", "min": 1, "max": 200},
        ]

    def initialize(self, context: ScanContext) -> None:
        self._options = build_options(context)

    async def scan(self, target: Target) -> list[Finding]:
        from phaseaccess.engine.scanner import scan as phaseaccess_scan

        options = self._options

        # Inject the target URL as the primary endpoint if none were configured
        if not options.extra_urls:
            options.extra_urls = [target.url]

        await self.ctx.events.progress("Starting PhaseAccess IDOR scan", 0.0)

        try:
            result = await asyncio.get_event_loop().run_in_executor(
                None, phaseaccess_scan, target.url, options
            )
        except Exception as exc:
            log.exception("PhaseAccess engine error for %s", target.url)
            await self.ctx.events.debug(f"PhaseAccess engine error: {exc}")
            return []

        findings = map_results(result)

        await self.ctx.events.progress(
            f"PhaseAccess complete — {len(findings)} IDOR finding(s)", 1.0
        )
        log.info("PhaseAccess: %d finding(s) for %s", len(findings), target.url)
        return findings
