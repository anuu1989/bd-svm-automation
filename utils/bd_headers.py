"""Black Duck media types and header construction."""
from __future__ import annotations

from config import settings


def media(kind: str = "default") -> str:
    """kind: default | auth | project | bom | vulnerability."""
    return settings.MEDIA.get(kind, kind)


def build(token: str | None = None, accept: str = "default", content: str | None = None) -> dict[str, str]:
    headers = {"Accept": media(accept)}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if content:
        headers["Content-Type"] = media(content)
    return headers
