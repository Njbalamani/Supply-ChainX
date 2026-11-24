from __future__ import annotations

from collections import defaultdict
from packaging.version import InvalidVersion, Version

from config.constants import Ecosystem

POPULAR_PACKAGES = {
    Ecosystem.PYTHON: {
        "requests", "django", "flask", "numpy", "pandas", "pytest", "setuptools", "pip",
        "urllib3", "cryptography", "pyyaml", "click", "boto3", "sqlalchemy", "celery",
    },
    Ecosystem.NODE: {
        "express", "lodash", "react", "axios", "typescript", "webpack", "eslint", "moment",
        "chalk", "commander", "debug", " minimist".strip(), "tough-cookie", "semver",
    },
    Ecosystem.JAVA: {
        "jackson-databind", "log4j-core", "spring-core", "guava", "commons-collections",
        "junit", "slf4j-api", "okhttp", "gson", "hibernate-core",
    },
}


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    previous = list(range(len(b) + 1))
    for i, char_a in enumerate(a, 1):
        current = [i]
        for j, char_b in enumerate(b, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (char_a != char_b)))
        previous = current
    return previous[-1]


def _compare_versions(old: str, new: str) -> str:
    try:
        old_v, new_v = Version(old), Version(new)
    except InvalidVersion:
        return "UNKNOWN"
    if new_v > old_v:
        return "UPGRADE"
    if new_v < old_v:
        return "DOWNGRADE"
    return "UNCHANGED"


def analyze_supply_chain_risk(scan) -> dict:
    from dependency_graph.models import RiskSignal
    from dependency_graph.service import build_networkx_graph

    RiskSignal.objects.filter(scan=scan, description__contains="previous scan").delete()
    dependencies = list(scan.dependencies.all())
    graph = build_networkx_graph(scan)
    signals_created = 0

    def add(dep, signal_type, severity, description, evidence=None):
        nonlocal signals_created
        RiskSignal.objects.create(
            scan=scan,
            dependency=dep,
            signal_type=signal_type,
            severity=severity,
            description=description,
            evidence=evidence or {},
        )
        signals_created += 1

    for dep in dependencies:
        if not dep.version:
            add(dep, "NO_PINNED_VERSION", "MEDIUM", f"{dep.name} has no exact version in the manifest.", {"specifier": dep.specifier})
        if not dep.license:
            add(dep, "UNKNOWN_LICENSE", "LOW", f"No license metadata available for {dep.name}.")
        deprecated = dep.metadata.get("deprecated")
        if deprecated:
            add(dep, "DEPRECATED_PACKAGE", "HIGH", f"Lockfile marks {dep.name} as deprecated.", {"message": str(deprecated)[:500]})
        if dep.ecosystem in POPULAR_PACKAGES:
            simple_name = dep.name.split("/")[-1].replace("@", "").lower()
            for popular in POPULAR_PACKAGES[dep.ecosystem]:
                if len(simple_name) >= 5 and simple_name != popular and _levenshtein(simple_name, popular) == 1:
                    add(
                        dep,
                        "NAME_SIMILARITY",
                        "HIGH",
                        f"{dep.name} name is one edit away from widely used package '{popular}'.",
                        {"similar_to": popular},
                    )
                    break
        if graph.has_node(dep.name) and graph.in_degree(dep.name) >= 5:
            add(dep, "CONCENTRATION", "MEDIUM", f"{dep.name} is depended on by {graph.in_degree(dep.name)} packages.", {"in_degree": graph.in_degree(dep.name)})

    previous = (
        scan.project.scans.filter(status="COMPLETED")
        .exclude(pk=scan.pk)
        .order_by("-created_at")
        .first()
    )
    history = []
    if previous:
        previous_versions = {d.name: d.version for d in previous.dependencies.all() if d.version}
        for dep in dependencies:
            if not dep.version or dep.name not in previous_versions:
                continue
            change = _compare_versions(previous_versions[dep.name], dep.version)
            history.append(
                {
                    "package": dep.name,
                    "previous_version": previous_versions[dep.name],
                    "current_version": dep.version,
                    "change": change,
                    "previous_scan_id": previous.pk,
                }
            )
            if change == "DOWNGRADE":
                add(
                    dep,
                    "VERSION_REGRESSION",
                    "HIGH",
                    f"{dep.name} was downgraded since scan #{previous.pk}.",
                    {"previous_version": previous_versions[dep.name], "current_version": dep.version},
                )

    return {
        "signals_created": signals_created,
        "update_history": history[:100],
        "previous_scan_id": previous.pk if previous else None,
    }
