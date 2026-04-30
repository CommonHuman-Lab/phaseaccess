"""
PhaseAccess — engine/reporter.py
Finding dataclasses and ScanResult for structured IDOR scan output.

Standalone-safe: stdlib only.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class IDORType(str, Enum):
  HORIZONTAL          = "horizontal_idor"      # peer-to-peer: user A accesses user B's object
  VERTICAL            = "vertical_idor"         # privilege escalation: regular user accesses admin object
  METHOD_BYPASS       = "method_bypass_idor"    # GET protected, PUT/DELETE not
  MASS_ASSIGNMENT     = "mass_assignment"        # injected owner/user field accepted by server
  PARAM_POLLUTION     = "param_pollution"        # ?id=own&id=victim — server picks victim
  SOFT_DELETE         = "soft_delete_idor"       # accessing logically deleted resources by ID
  BLIND               = "blind_idor"             # no data returned but side-effect observable


class IDType(str, Enum):
  INTEGER             = "integer"
  UUID_V1             = "uuid_v1"               # timestamp-based — predictable
  UUID_V4             = "uuid_v4"               # random
  UUID_UNKNOWN        = "uuid_unknown"
  BASE64              = "base64"
  JWT                 = "jwt"
  HASH_MD5            = "hash_md5"
  HASH_SHA1           = "hash_sha1"
  HASH_SHA256         = "hash_sha256"
  SLUG                = "slug"                  # human-readable e.g. "my-document"
  SNOWFLAKE           = "snowflake"             # Twitter/Discord-style epoch IDs
  UNKNOWN             = "unknown"


class Confidence(str, Enum):
  CONFIRMED   = "confirmed"    # multi-session: response contains other user's data
  HIGH        = "high"         # strong signals: 200 + content differs + ownership fields match
  MEDIUM      = "medium"       # 200 + different content but no ownership confirmation
  LOW         = "low"          # status code diff only, or heuristic only
  INFO        = "info"         # ID enumeration possible but no access confirmed


class IDORLocation(str, Enum):
  QUERY_PARAM   = "query_param"
  PATH_SEGMENT  = "path_segment"
  POST_BODY     = "post_body"
  JSON_BODY     = "json_body"
  HEADER        = "header"
  COOKIE        = "cookie"
  JWT_CLAIM     = "jwt_claim"


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------

@dataclass
class IDORFinding:
  # What was found
  idor_type:   IDORType
  confidence:  Confidence
  location:    IDORLocation

  # Target details
  url:         str
  method:      str                    # GET POST PUT DELETE PATCH
  parameter:   str                    # param name or path position e.g. "id", "path[2]"
  id_type:     IDType

  # The tamper that triggered it
  original_value:  str
  tampered_value:  str

  # Response comparison
  baseline_status:  int
  tampered_status:  int
  baseline_length:  int
  tampered_length:  int

  # Ownership / semantic evidence
  owner_fields_leaked: List[str] = field(default_factory=list)  # e.g. ["email", "user_id"]
  evidence_snippet:    str = ""    # excerpt from tampered response

  # Role comparison (multi-session mode)
  session_a_label: str = ""
  session_b_label: str = ""

  # Extra context
  notes: str = ""

  def to_dict(self) -> Dict[str, Any]:
    return {
      "type":               self.idor_type,
      "confidence":         self.confidence,
      "location":           self.location,
      "url":                self.url,
      "method":             self.method,
      "parameter":          self.parameter,
      "id_type":            self.id_type,
      "original_value":     self.original_value,
      "tampered_value":     self.tampered_value,
      "baseline_status":    self.baseline_status,
      "tampered_status":    self.tampered_status,
      "baseline_length":    self.baseline_length,
      "tampered_length":    self.tampered_length,
      "owner_fields_leaked": self.owner_fields_leaked,
      "evidence_snippet":   self.evidence_snippet,
      "session_a_label":    self.session_a_label,
      "session_b_label":    self.session_b_label,
      "notes":              self.notes,
    }


# ---------------------------------------------------------------------------
# Top-level ScanResult
# ---------------------------------------------------------------------------

@dataclass
class ScanResult:
  target:       str
  started_at:   float = field(default_factory=time.time)
  finished_at:  float = 0.0
  duration_s:   float = 0.0

  # Session info
  session_a_label: str = "session_a"
  session_b_label: str = ""   # empty = single-session mode

  # Stats
  endpoints_tested:  int = 0
  parameters_tested: int = 0
  requests_sent:     int = 0
  id_types_found:    List[str] = field(default_factory=list)

  # Findings
  findings: List[IDORFinding] = field(default_factory=list)

  # Info: IDs harvested from responses (useful for chaining)
  harvested_ids: Dict[str, List[str]] = field(default_factory=dict)  # param_name -> [values]

  # Log + errors
  log:    List[str] = field(default_factory=list)
  errors: List[str] = field(default_factory=list)

  def finish(self) -> "ScanResult":
    self.finished_at = time.time()
    self.duration_s  = round(self.finished_at - self.started_at, 2)
    return self

  @property
  def success(self) -> bool:
    return not bool(self.errors) or bool(self.findings)

  @property
  def total_findings(self) -> int:
    return len(self.findings)

  @property
  def confirmed_findings(self) -> int:
    return sum(1 for f in self.findings if f.confidence == Confidence.CONFIRMED)

  def to_dict(self) -> Dict[str, Any]:
    return {
      "success":            self.success,
      "target":             self.target,
      "duration_s":         self.duration_s,
      "session_a_label":    self.session_a_label,
      "session_b_label":    self.session_b_label,
      "endpoints_tested":   self.endpoints_tested,
      "parameters_tested":  self.parameters_tested,
      "requests_sent":      self.requests_sent,
      "id_types_found":     self.id_types_found,
      "total_findings":     self.total_findings,
      "confirmed_findings": self.confirmed_findings,
      "findings":           [f.to_dict() for f in self.findings],
      "harvested_ids":      self.harvested_ids,
      "errors":             self.errors,
      "log":                self.log,
    }
