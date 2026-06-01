# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Map native PhaseAccess findings → GloomProxy SDK Finding objects."""
from __future__ import annotations

from gloomproxy_sdk import Finding

from phaseaccess.engine.reporter import Confidence, IDORFinding, ScanResult

_SCANNER = "phaseaccess"

_CONF_MAP = {
    "confirmed": 0.98,
    "high":      0.85,
    "medium":    0.65,
    "low":       0.40,
}

_SEVERITY_MAP = {
    "confirmed": "critical",
    "high":      "high",
    "medium":    "medium",
    "low":       "low",
}


def _map_idor(f: IDORFinding) -> Finding:
    conf_key = str(f.confidence).lower().split(".")[-1]  # handle enum repr
    confidence = _CONF_MAP.get(conf_key, 0.65)
    severity = _SEVERITY_MAP.get(conf_key, "medium")

    leaked = ", ".join(f.owner_fields_leaked) if f.owner_fields_leaked else "none detected"
    evidence = (
        f.evidence_snippet
        or f"IDOR via {f.location.value} parameter '{f.parameter}': "
        f"original={f.original_value!r} → tampered={f.tampered_value!r} "
        f"({f.baseline_status}→{f.tampered_status}, Δbytes={f.tampered_length - f.baseline_length})"
    )

    return Finding(
        scanner=_SCANNER,
        type="idor",
        severity=severity,
        target=f.url,
        evidence=evidence,
        title=f"IDOR — {f.parameter} ({f.location.value})",
        description=(
            f"Insecure Direct Object Reference in parameter '{f.parameter}' "
            f"({f.location.value}). Tampered value '{f.tampered_value}' returned "
            f"a {f.tampered_status} response. Leaked fields: {leaked}."
        ),
        confidence=confidence,
        request=f"URL: {f.url}\nMethod: {f.method}\nParameter: {f.parameter}\n"
                f"Original: {f.original_value}\nTampered: {f.tampered_value}",
        extra={
            "parameter": f.parameter,
            "method": f.method,
            "location": f.location.value,
            "idor_type": f.idor_type.value,
            "id_type": f.id_type.value,
            "original_value": f.original_value,
            "tampered_value": f.tampered_value,
            "baseline_status": f.baseline_status,
            "tampered_status": f.tampered_status,
            "owner_fields_leaked": f.owner_fields_leaked,
            "session_a_label": f.session_a_label,
            "session_b_label": f.session_b_label,
        },
        tags=[
            "idor",
            "access-control",
            f"location:{f.location.value}",
            f"type:{f.idor_type.value}",
        ],
    )


def map_results(result: ScanResult) -> list[Finding]:
    """Convert a PhaseAccess ScanResult into a list of SDK Finding objects."""
    findings: list[Finding] = []
    for native in result.findings:
        try:
            findings.append(_map_idor(native).validate())
        except Exception:
            pass
    return findings
