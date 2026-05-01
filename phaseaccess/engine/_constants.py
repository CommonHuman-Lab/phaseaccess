"""
PhaseAccess — engine/_constants.py
Shared constants used across multiple engine modules.
"""

from __future__ import annotations

# JSON response keys that indicate object ownership / identity.
# Used in both fingerprint.py (for extraction) and extractor.py (for harvesting).
OWNERSHIP_KEYS: frozenset[str] = frozenset({
    'user_id', 'userid', 'userId',
    'owner_id', 'ownerId', 'owner',
    'account_id', 'accountId',
    'created_by', 'createdBy',
    'author_id', 'authorId',
    'email', 'username', 'handle', 'phone',
    'assigned_to', 'assignedTo',
    'fullName',
})
