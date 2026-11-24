from __future__ import annotations

import base64
import hashlib
import json
import uuid
from datetime import datetime, timezone

from config.constants import DependencyType, Ecosystem

SPDX_LICENSES = {
    "MIT", "APACHE-2.0", "APACHE 2.0", "BSD-2-CLAUSE", "BSD-3-CLAUSE", "ISC", "MPL-2.0",
    "GPL-2.0", "GPL-2.0-ONLY", "GPL-3.0", "GPL-3.0-ONLY", "LGPL-2.1", "LGPL-3.0",
    "AGPL-3.0", "GPLV2", "GPLV3", "EPL-2.0", "CDDL-1.0", "UNLICENSE", "CC0-1.0",
}


def _license_entries(license_value: str) -> list[dict]:
    if not license_value:
        return []
    value = license_value.strip()
    upper = value.upper().replace(" ", "-")
    if upper in SPDX_LICENSES or upper.startswith(("APACHE-", "GPL-", "LGPL-", "AGPL-", "MIT-", "BSD-", "MPL-")):
        return [{"license": {"id": upper, "url": f"https://spdx.org/licenses/{upper}.html"}}]
    return [{"license": {"name": value}}]


def _component_type(ecosystem: str) -> str:
    return "library"


def build_cyclonedx_document(scan) -> dict:
    project = scan.project
    dependencies = list(scan.dependencies.all())
    serial = f"urn:uuid:{uuid.uuid4()}"
    root_ref = f"supplychainx:project:{project.pk}"

    components = []
    dep_refs: dict[int, str] = {}
    for dep in dependencies:
        purl = dep.purl
        dep_refs[dep.pk] = purl
        component = {
            "type": _component_type(dep.ecosystem),
            "bom-ref": purl,
            "name": dep.name,
            "version": dep.version or "UNSPECIFIED",
            "purl": purl,
            "properties": [
                {"name": "supplychainx:is-direct", "value": str(dep.is_direct).lower()},
                {"name": "supplychainx:source-file", "value": dep.source_file},
                {"name": "supplychainx:dependency-type", "value": dep.dependency_type},
                {"name": "supplychainx:ecosystem", "value": dep.ecosystem},
            ],
        }
        if dep.license:
            component["licenses"] = _license_entries(dep.license)
        if dep.metadata.get("integrity"):
            try:
                encoded = dep.metadata["integrity"].split("-", 1)[-1]
                digest_hex = base64.b64decode(encoded).hex()
                component["hashes"] = [{"alg": "SHA-256", "content": digest_hex}]
            except (ValueError, TypeError):
                pass
        components.append(component)

    graph = [{"ref": root_ref, "dependsOn": [dep_refs[d.pk] for d in dependencies if d.is_direct and d.pk in dep_refs]}]
    by_name: dict[str, list[str]] = {}
    for dep in dependencies:
        if dep.parent_name:
            by_name.setdefault(dep.parent_name.lower(), []).append(dep_refs[dep.pk])
    for dep in dependencies:
        children = by_name.get(dep.name.lower(), [])
        if children:
            graph.append({"ref": dep_refs[dep.pk], "dependsOn": sorted(set(children))})

    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "tools": [
                {
                    "vendor": "SupplyChainX",
                    "name": "SupplyChainX SBOM Generator",
                    "version": "1.0.0",
                }
            ],
            "component": {
                "type": "application",
                "bom-ref": root_ref,
                "name": project.name,
                "version": f"scan-{scan.pk}",
                "description": project.description or f"SupplyChainX scan #{scan.pk}",
                "externalReferences": [
                    {"type": "vcs", "url": project.repository_url, "comment": "Project repository"}
                ] if project.repository_url else [],
                "properties": [
                    {"name": "supplychainx:organization", "value": project.organization.name},
                    {"name": "supplychainx:scan-id", "value": str(scan.pk)},
                ],
            },
        },
        "components": components,
        "dependencies": graph,
    }
    return document


def generate_sbom(scan):
    from .models import SBOM

    existing = SBOM.objects.filter(scan=scan).first()
    if existing:
        return existing

    document = build_cyclonedx_document(scan)
    payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    checksum = hashlib.sha256(payload).hexdigest()
    sbom, _ = SBOM.objects.update_or_create(
        scan=scan,
        defaults={
            "spec_version": document["specVersion"],
            "serial_number": document["serialNumber"],
            "bom_ref": f"supplychainx:project:{scan.project_id}",
            "document": document,
            "sha256": checksum,
        },
    )
    return sbom
