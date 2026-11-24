from __future__ import annotations

from collections import Counter
from typing import Any

from config.constants import LicenseCategory

STRONG_COPYLEFT = {
    "GPL-2.0", "GPL-2.0-ONLY", "GPL-3.0", "GPL-3.0-ONLY", "AGPL-3.0", "AGPL-3.0-ONLY",
}
WEAK_COPYLEFT = {"LGPL-2.1", "LGPL-3.0", "MPL-2.0", "EPL-2.0", "CDDL-1.0"}
PERMISSIVE = {
    "MIT", "APACHE-2.0", "BSD-2-CLAUSE", "BSD-3-CLAUSE", "ISC", "UNLICENSE", "CC0-1.0", "ZLIB",
}
COMMERCIAL = {"PROPRIETARY", "COMMERCIAL", "CC-BY-NC", "SSPL-1.0", "BUSL-1.1"}

INCOMPATIBLE_PAIRS = {
    frozenset({"GPL-2.0", "APACHE-2.0"}),
    frozenset({"GPL-2.0-ONLY", "APACHE-2.0"}),
}


def normalize_license(value: str) -> str:
    if not value:
        return ""
    cleaned = value.strip().replace(" ", "-").upper()
    aliases = {
        "APACHE2": "APACHE-2.0",
        "APACHE-2": "APACHE-2.0",
        "GPLV2": "GPL-2.0",
        "GPLV3": "GPL-3.0",
        "LGPL": "LGPL-2.1",
        "MIT/LICENSE": "MIT",
    }
    return aliases.get(cleaned, cleaned)


def classify_license(spdx_id: str) -> str:
    if spdx_id in STRONG_COPYLEFT:
        return LicenseCategory.STRONG_COPYLEFT
    if spdx_id in WEAK_COPYLEFT:
        return LicenseCategory.WEAK_COPYLEFT
    if spdx_id in PERMISSIVE:
        return LicenseCategory.PERMISSIVE
    if spdx_id in COMMERCIAL:
        return LicenseCategory.COMMERCIAL
    return LicenseCategory.UNKNOWN


def analyze_licenses(scan) -> dict[str, Any]:
    from .models import LicenseRecord, LicenseReport

    LicenseRecord.objects.filter(scan=scan).delete()
    raw_records = []
    for dep in scan.dependencies.all():
        license_value = dep.license or dep.metadata.get("license", "")
        spdx_id = normalize_license(license_value)
        category = classify_license(spdx_id)
        reason_parts = []
        requires_review = False
        compatible = True
        if category == LicenseCategory.UNKNOWN:
            reason_parts.append("License identifier missing or not in the built-in SPDX classification set.")
            requires_review = True
            compatible = False
        elif category == LicenseCategory.STRONG_COPYLEFT:
            reason_parts.append("Strong copyleft license may impose source-disclosure obligations.")
            requires_review = True
        elif category == LicenseCategory.COMMERCIAL:
            reason_parts.append("Commercial/restricted license requires legal review.")
            requires_review = True
        elif category == LicenseCategory.WEAK_COPYLEFT:
            reason_parts.append("Weak copyleft license; verify dynamic linking and modification terms.")
            requires_review = True
        raw_records.append(
            {
                "scan": scan,
                "dependency": dep,
                "package_name": dep.name,
                "version": dep.version,
                "license_id": license_value,
                "spdx_id": spdx_id,
                "category": category,
                "compatible": compatible,
                "requires_review": requires_review,
                "reason": " ".join(reason_parts),
                "source": dep.source_file,
            }
        )

    present_ids = {r["spdx_id"] for r in raw_records if r["spdx_id"]}
    conflicts = [pair for pair in INCOMPATIBLE_PAIRS if pair <= present_ids]
    for record in raw_records:
        for pair in conflicts:
            if record["spdx_id"] in pair:
                record["compatible"] = False
                record["requires_review"] = True
                record["reason"] += f" Potentially incompatible license combination: {' + '.join(sorted(pair))}."
    for record in raw_records:
        LicenseRecord.objects.create(**record)

    categories = Counter(r["category"] for r in raw_records)
    summary = {
        "total": len(raw_records),
        "by_category": dict(categories),
        "requires_review": sum(1 for r in raw_records if r["requires_review"]),
        "incompatible": sum(1 for r in raw_records if not r["compatible"]),
        "known_license_coverage": round(
            sum(1 for r in raw_records if r["category"] != LicenseCategory.UNKNOWN) / max(1, len(raw_records)), 3
        ),
        "detected_conflicts": [" + ".join(sorted(pair)) for pair in conflicts],
    }
    LicenseReport.objects.update_or_create(scan=scan, defaults={"summary": summary})
    return summary
