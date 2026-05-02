# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab

"""
PhaseAccess — engine/__init__.py
Public API for the PhaseAccess engine.

Usage:
    from phaseaccess.engine import scan, ScanOptions
    from phaseaccess.engine.reporter import ScanResult, IDORFinding, Confidence
    from phaseaccess.engine.session import Session, SessionPair, pair_from_config
"""

from .scanner import scan, ScanOptions
from .reporter import ScanResult, IDORFinding, IDORType, Confidence, IDORLocation, IDType, CONFIDENCE_RANK

__all__ = [
  "scan",
  "ScanOptions",
  "ScanResult",
  "IDORFinding",
  "IDORType",
  "Confidence",
  "CONFIDENCE_RANK",
  "IDORLocation",
  "IDType",
]