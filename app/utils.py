from __future__ import annotations

import re


def sanitize_label(raw: str, *, max_len: int = 63, allow_dots: bool = False) -> str:
    """Normalize user-controlled identifiers into stable lowercase labels."""
    value = str(raw).strip().lower()
    if not value:
        return ""

    value = value.replace("_", "-").replace(" ", "-")
    if allow_dots:
        value = re.sub(r"[^a-z0-9.-]", "-", value)
        value = re.sub(r"\.{2,}", ".", value)
        value = re.sub(r"-+\.-+|\.-+|-+\.", ".", value)
    else:
        value = re.sub(r"[^a-z0-9-]", "-", value)
    value = re.sub(r"-{2,}", "-", value)
    value = value.strip("-.")
    if max_len <= 0:
        return value
    return value[:max_len]
