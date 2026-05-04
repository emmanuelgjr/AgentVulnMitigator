"""Lightweight SQL guard for tool-issued queries.

Goal: catch the common shapes of agent-induced SQL abuse — multi-statement
batches, comment-based bypasses, schema-mutating DDL, and full-table writes
without a WHERE clause. This is *not* a SQL parser; pair with parameterized
queries on the tool side.
"""
from __future__ import annotations

import re

_MULTI = re.compile(r";\s*\S")
_COMMENT = re.compile(r"--|/\*|\*/|#")
_DDL = re.compile(r"\b(?:DROP|TRUNCATE|ALTER|CREATE|GRANT|REVOKE)\b", re.IGNORECASE)
_WRITE_NO_WHERE = re.compile(r"\b(?:UPDATE|DELETE)\b(?![^;]*\bWHERE\b)", re.IGNORECASE)
_UNION = re.compile(r"\bUNION\b\s+(?:ALL\s+)?\bSELECT\b", re.IGNORECASE)


def validate_sql_query(
    query: str,
    *,
    allow_writes: bool = False,
    allow_ddl: bool = False,
) -> str | None:
    if not isinstance(query, str) or not query.strip():
        return "empty query"

    stripped = query.strip().rstrip(";")

    if _MULTI.search(stripped):
        return "multi-statement queries are not allowed"

    if _COMMENT.search(stripped):
        return "SQL comments are not allowed"

    if _UNION.search(stripped):
        return "UNION SELECT is not allowed"

    if _DDL.search(stripped) and not allow_ddl:
        return "DDL statements are not allowed by policy"

    if not allow_writes and re.search(r"\b(?:INSERT|UPDATE|DELETE|REPLACE|MERGE)\b", stripped, re.IGNORECASE):
        return "write statements are not allowed by policy"

    if _WRITE_NO_WHERE.search(stripped):
        return "UPDATE/DELETE without a WHERE clause is not allowed"

    return None
