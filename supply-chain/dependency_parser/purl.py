"""Package URL (purl) construction for CycloneDX component identities."""
from __future__ import annotations

from urllib.parse import quote


def make_purl(ecosystem: str, name: str, version: str = "", metadata: dict | None = None) -> str:
    metadata = metadata or {}
    clean_version = (version or "").strip()
    if ecosystem == "PYTHON":
        base = f"pkg:pypi/{quote(name.strip(), safe='._-')}"
    elif ecosystem == "NODE":
        base = f"pkg:npm/{quote(name.strip().replace('@', '%40'), safe='/@._-')}"
    elif ecosystem == "JAVA":
        group = metadata.get("group") or (name.split(":", 1)[0] if ":" in name else "")
        artifact = metadata.get("artifact") or (name.split(":", 1)[1] if ":" in name else name)
        base = f"pkg:maven/{quote(group, safe='._-')}/{quote(artifact, safe='._-')}" if group else f"pkg:maven/{quote(artifact, safe='._-')}"
    else:
        base = f"pkg:generic/{quote(name.strip(), safe='._-')}"
    return f"{base}@{quote(clean_version, safe='._-+~')}" if clean_version else base
