from __future__ import annotations

import json
import logging

import requests
from django.conf import settings
from packaging.version import InvalidVersion, Version

from config.constants import Priority, Severity

logger = logging.getLogger("supplychainx")

PRIORITY_RANK = {
    Priority.CRITICAL: 4,
    Priority.HIGH: 3,
    Priority.MEDIUM: 2,
    Priority.LOW: 1,
}


def _priority_for_severity(severity: str) -> str:
    return {
        Severity.CRITICAL: Priority.CRITICAL,
        Severity.HIGH: Priority.HIGH,
        Severity.MEDIUM: Priority.MEDIUM,
        Severity.LOW: Priority.LOW,
    }.get(severity, Priority.MEDIUM)


def _select_fixed_version(current: str, fixed_versions: list[str]) -> str:
    if not fixed_versions:
        return ""
    try:
        current_version = Version(current) if current else Version("0.0.0")
    except InvalidVersion:
        current_version = Version("0.0.0")
    candidates = []
    for raw in fixed_versions:
        try:
            version = Version(raw)
        except InvalidVersion:
            continue
        if version > current_version:
            candidates.append(version)
    if not candidates:
        return ""
    return str(min(candidates))


def _create(scan, **kwargs):
    from .models import Recommendation

    priority = kwargs.get("priority", Priority.MEDIUM)
    kwargs["priority_rank"] = PRIORITY_RANK.get(priority, 2)
    return Recommendation.objects.create(scan=scan, **kwargs)


def generate_recommendations(scan) -> dict:
    from .models import Recommendation, RecommendationType

    Recommendation.objects.filter(scan=scan).delete()
    created = 0

    for vuln in scan.vulnerabilities.all().order_by("-cvss_score"):
        priority = _priority_for_severity(vuln.severity)
        fixed = _select_fixed_version(vuln.package_version, vuln.fixed_versions)
        sources = ", ".join(vuln.sources) if vuln.sources else vuln.source
        if fixed:
            steps = [
                f"Change the {vuln.package_name} constraint to >= {fixed} in the manifest that declares it.",
                "Regenerate the lockfile and commit the updated resolution.",
                "Run the project test suite and integration checks.",
                "Re-scan the project to confirm the advisory no longer matches.",
            ]
            _create(
                scan,
                vulnerability=vuln,
                dependency=vuln.dependency,
                type=RecommendationType.UPGRADE,
                priority=priority,
                title=f"Upgrade {vuln.package_name} {vuln.package_version} to {fixed}",
                explanation=(
                    f"{vuln.cve_or_id} affects {vuln.package_name} {vuln.package_version} according to {sources}. "
                    f"The advisory lists {fixed} as a fixed release."
                ),
                recommended_version=fixed,
                upgrade_steps=steps,
                risks=f"Review upstream release notes for breaking changes between {vuln.package_version} and {fixed}.",
                confidence=0.95,
                source="RULE_ENGINE",
            )
            created += 1
        else:
            _create(
                scan,
                vulnerability=vuln,
                dependency=vuln.dependency,
                type=RecommendationType.MITIGATION,
                priority=priority,
                title=f"Review mitigation options for {vuln.package_name} {vuln.package_version}",
                explanation=(
                    f"{vuln.cve_or_id} was reported by {sources}. No fixed version was published in the "
                    "queried advisory data at scan time, so apply compensating controls and re-check upstream."
                ),
                upgrade_steps=[
                    f"Open the advisory at {vuln.source_url or 'the upstream advisory page'} and confirm affected ranges.",
                    "Restrict exposure to the affected code path where possible.",
                    "Schedule a re-scan when upstream publishes a patched release.",
                ],
                risks="Without a verified fixed release, upgrading blindly may not resolve the advisory.",
                confidence=0.8,
                source="RULE_ENGINE",
            )
            created += 1

    for dep in scan.dependencies.all():
        if not dep.version:
            _create(
                scan,
                dependency=dep,
                type=RecommendationType.PIN_VERSION,
                priority=Priority.MEDIUM,
                title=f"Pin an exact version for {dep.name}",
                explanation=(
                    f"Manifest {dep.source_file} declares '{dep.specifier or 'an unpinned range'}' rather than an exact "
                    "version, so vulnerability matching cannot use a precise release."
                ),
                upgrade_steps=["Select a reviewed exact version and update the manifest/lockfile."],
                risks="Pinning requires a controlled update process to avoid stale dependencies.",
                confidence=0.9,
                source="RULE_ENGINE",
            )
            created += 1

    for record in scan.license_records.filter(requires_review=True)[:25]:
        _create(
            scan,
            type=RecommendationType.LICENSE_REVIEW,
            priority=Priority.HIGH if not record.compatible else Priority.MEDIUM,
            title=f"License review required for {record.package_name}",
            explanation=record.reason or f"License '{record.license_id}' requires manual review.",
            upgrade_steps=["Confirm the license with the package metadata and your distribution policy."],
            risks="License obligations may affect distribution.",
            confidence=0.85,
            source="RULE_ENGINE",
        )
        created += 1

    for signal in scan.risk_signals.filter(severity="HIGH")[:25]:
        _create(
            scan,
            type=RecommendationType.RISK_REVIEW,
            priority=Priority.HIGH,
            title=f"Investigate {signal.signal_type} signal",
            explanation=signal.description,
            upgrade_steps=["Validate the signal against upstream package provenance and your allowed-package policy."],
            risks="Heuristic signals require human confirmation.",
            confidence=0.6,
            source="RULE_ENGINE",
        )
        created += 1

    summary = {
        "rule_based": created,
        "llm": 0,
        "provider": "rule_engine",
        "warnings": [],
    }
    if settings.AI_PROVIDER == "openai" and settings.OPENAI_API_KEY:
        llm_result = _openai_summary(scan)
        summary["llm"] = llm_result.get("created", 0)
        summary["provider"] = "openai"
        summary["warnings"].extend(llm_result.get("warnings", []))
    elif settings.AI_PROVIDER == "openai":
        summary["warnings"].append("AI_PROVIDER=openai but OPENAI_API_KEY is not configured.")
    return summary


def _openai_summary(scan) -> dict:
    findings = [
        {
            "package": v.package_name,
            "version": v.package_version,
            "advisory": v.cve_or_id,
            "severity": v.severity,
            "sources": v.sources,
            "fixed_versions": v.fixed_versions,
        }
        for v in scan.vulnerabilities.all()[:30]
    ]
    context = {
        "project": scan.project.name,
        "ecosystems": sorted({d.ecosystem for d in scan.dependencies.all()}),
        "dependency_count": scan.dependencies.count(),
        "findings": findings,
        "risk_score": scan.risk_score,
    }
    payload = {
        "model": settings.OPENAI_MODEL,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a supply-chain security assistant. Use only the supplied scan facts. "
                    "Never invent CVE identifiers, versions, or advisory details. Return JSON with "
                    "title, explanation, priority (CRITICAL/HIGH/MEDIUM/LOW), and risks."
                ),
            },
            {"role": "user", "content": json.dumps(context)},
        ],
        "temperature": 0.1,
        "response_format": {"type": "json_object"},
    }
    try:
        response = requests.post(
            settings.OPENAI_API_URL,
            json=payload,
            timeout=settings.HTTP_TIMEOUT,
            headers={
                "Authorization": f"Bearer {settings.OPENAI_API_KEY}",
                "Content-Type": "application/json",
            },
        )
        response.raise_for_status()
        content = response.json()["choices"][0]["message"]["content"]
        parsed = json.loads(content)
    except (requests.RequestException, KeyError, ValueError, json.JSONDecodeError) as exc:
        logger.warning("OpenAI recommendation request failed: %s", exc)
        return {"created": 0, "warnings": [f"AI provider unavailable: {exc}"]}

    priority = str(parsed.get("priority", "MEDIUM")).upper()
    if priority not in PRIORITY_RANK:
        priority = Priority.MEDIUM
    _create(
        scan,
        type="AI_SUMMARY",
        priority=priority,
        title=str(parsed.get("title", "AI remediation summary"))[:300],
        explanation=str(parsed.get("explanation", "")),
        risks=str(parsed.get("risks", "")),
        confidence=0.7,
        source="OPENAI",
        raw=parsed,
    )
    return {"created": 1, "warnings": []}
