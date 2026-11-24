"""HTTP clients and normalizers for OSV.dev and NVD CVE APIs.

All vulnerability data returned by these helpers comes from live upstream APIs.
Failures are reported explicitly and never replaced with synthetic findings.
"""
from __future__ import annotations

import logging
import math
import re
from datetime import datetime, timezone
from typing import Any

import requests
from django.conf import settings

logger = logging.getLogger("supplychainx")

OSV_ECOSYSTEMS = {"PYTHON": "PyPI", "NODE": "npm", "JAVA": "Maven"}


class IntelUnavailable(RuntimeError):
    pass


def parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def record_source_status(name: str, ok: bool, message: str = "") -> None:
    from .models import IntelSourceStatus

    status, _ = IntelSourceStatus.objects.get_or_create(name=name)
    now = datetime.now(timezone.utc)
    status.status = "OK" if ok else "UNAVAILABLE"
    status.message = message[:2000]
    status.last_attempt = now
    if ok:
        status.last_success = now
    status.request_count += 1
    status.save(update_fields=["status", "message", "last_attempt", "last_success", "request_count"])


def _field(obj, name: str, default=""):
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def osv_query_batch(dependencies: list) -> list[dict]:
    """Return a list of OSV result objects aligned with the input order."""
    if not dependencies:
        return []

    results: list[dict] = []
    for start in range(0, len(dependencies), 100):
        chunk = dependencies[start : start + 100]
        queries = []
        for dep in chunk:
            ecosystem = OSV_ECOSYSTEMS.get(_field(dep, "ecosystem", ""))
            version = str(_field(dep, "version", "") or "").strip()
            name = str(_field(dep, "name", "") or "")
            if not ecosystem or not version or not name:
                queries.append({})
                continue
            queries.append(
                {
                    "package": {"name": name, "ecosystem": ecosystem},
                    "version": version,
                }
            )
        valid_queries = [q for q in queries if q]
        if not valid_queries:
            results.extend({} for _ in chunk)
            continue
        try:
            response = requests.post(
                settings.OSV_QUERY_URL,
                json={"queries": valid_queries},
                timeout=settings.HTTP_TIMEOUT,
                headers={"User-Agent": "SupplyChainX/1.0"},
            )
            response.raise_for_status()
            payload = response.json()
        except (requests.RequestException, ValueError) as exc:
            record_source_status("OSV", False, f"Batch query failed: {exc}")
            raise IntelUnavailable(f"OSV query failed: {exc}") from exc

        batch_results = payload.get("results") or []
        record_source_status("OSV", True, f"Queried {len(valid_queries)} packages.")
        valid_iter = iter(batch_results)
        for query in queries:
            if not query:
                results.append({})
            else:
                results.append(next(valid_iter, {}))
    return results


def osv_fetch_vuln(vuln_id: str) -> dict:
    url = settings.OSV_VULN_URL.format(vuln_id=vuln_id)
    try:
        response = requests.get(url, timeout=settings.HTTP_TIMEOUT, headers={"User-Agent": "SupplyChainX/1.0"})
        response.raise_for_status()
        return response.json()
    except (requests.RequestException, ValueError) as exc:
        logger.warning("Could not fetch OSV details for %s: %s", vuln_id, exc)
        return {}


_CVSS31_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {"N": 0.85, "L": 0.62, "H": 0.27},
    "PR_CHANGED": {"N": 0.85, "L": 0.68, "H": 0.5},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def cvss_score_from_vector(vector: str) -> float | None:
    """Compute CVSS v3.x base score from an official vector string."""
    if not vector or "CVSS:3" not in vector:
        return None
    parts = dict(part.split(":", 1) for part in vector.split("/") if ":" in part)
    try:
        changed = parts.get("S") == "C"
        exploitability = (
            8.22
            * _CVSS31_WEIGHTS["AV"][parts["AV"]]
            * _CVSS31_WEIGHTS["AC"][parts["AC"]]
            * _CVSS31_WEIGHTS["PR_CHANGED" if changed else "PR"][parts["PR"]]
            * _CVSS31_WEIGHTS["UI"][parts["UI"]]
        )
        iss = 1 - (
            (1 - _CVSS31_WEIGHTS["C"][parts["C"]])
            * (1 - _CVSS31_WEIGHTS["I"][parts["I"]])
            * (1 - _CVSS31_WEIGHTS["A"][parts["A"]])
        )
        impact = 6.42 * iss if not changed else 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        if impact <= 0:
            return 0.0
        raw = min(impact + exploitability, 10) if changed else min(impact + exploitability, 10)
        return round(math.ceil(raw * 10) / 10, 1)
    except (KeyError, ValueError):
        return None


def severity_from_score(score: float | None) -> str:
    from config.constants import Severity

    if score is None:
        return Severity.UNKNOWN
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


def normalize_severity(value: str) -> str:
    from config.constants import Severity

    mapping = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "moderate": Severity.MEDIUM,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
    }
    return mapping.get((value or "").lower(), Severity.UNKNOWN)


def fix_versions_for(vuln: dict, ecosystem: str) -> list[str]:
    fixes: list[str] = []
    expected = OSV_ECOSYSTEMS.get(ecosystem, "")
    for affected in vuln.get("affected") or []:
        package = affected.get("package") or {}
        if expected and package.get("ecosystem") and package["ecosystem"].lower() != expected.lower():
            continue
        for item in affected.get("ranges") or []:
            for event in item.get("events") or []:
                if "fixed" in event and event["fixed"]:
                    fixes.append(event["fixed"])
        if affected.get("versions"):
            pass
    return sorted(set(fixes))


def normalize_osv_vuln(vuln: dict) -> dict[str, Any]:
    severity_entries = vuln.get("severity") or []
    vector = next((s.get("score", "") for s in severity_entries if s.get("type") == "CVSS_V3"), "")
    score = cvss_score_from_vector(vector)
    db_specific = vuln.get("database_specific") or {}
    if score is None and isinstance(db_specific.get("cvss"), (int, float)):
        score = float(db_specific["cvss"])
    severity = normalize_severity(db_specific.get("severity", "")) if db_specific.get("severity") else severity_from_score(score)
    aliases = list(vuln.get("aliases") or [])
    cve_ids = [a for a in aliases if re.fullmatch(r"CVE-\d{4}-\d{4,}", a, re.IGNORECASE)]
    details = vuln.get("details") or ""
    references = [r.get("url", "") for r in vuln.get("references") or [] if r.get("url")]
    return {
        "vuln_id": vuln.get("id", ""),
        "cve_ids": cve_ids,
        "aliases": aliases,
        "severity": severity,
        "cvss_score": score,
        "cvss_vector": vector,
        "summary": (vuln.get("summary") or details[:400]).strip(),
        "description": details.strip(),
        "references": references,
        "published": parse_dt(vuln.get("published")),
        "modified": parse_dt(vuln.get("modified")),
        "raw": vuln,
    }


def nvd_fetch_cve(cve_id: str) -> dict | None:
    if not cve_id or not settings.ENABLE_NVD_ENRICHMENT:
        return None
    headers = {"User-Agent": "SupplyChainX/1.0"}
    if settings.NVD_API_KEY:
        headers["apiKey"] = settings.NVD_API_KEY
    try:
        response = requests.get(
            settings.NVD_CVE_URL,
            params={"cveId": cve_id},
            timeout=settings.HTTP_TIMEOUT,
            headers=headers,
        )
        response.raise_for_status()
        vulnerabilities = response.json().get("vulnerabilities") or []
        if not vulnerabilities:
            record_source_status("NVD", True, f"No record for {cve_id}.")
            return None
        record_source_status("NVD", True, f"Fetched {cve_id}.")
        return vulnerabilities[0].get("cve", {})
    except (requests.RequestException, ValueError) as exc:
        logger.warning("NVD lookup failed for %s: %s", cve_id, exc)
        record_source_status("NVD", False, f"Lookup failed: {exc}")
        return None


def normalize_nvd_cve(cve: dict) -> dict[str, Any]:
    metrics = cve.get("metrics") or {}
    metric = None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            metric = metrics[key][0]
            break
    cvss_data = (metric or {}).get("cvssData") or {}
    score = cvss_data.get("baseScore")
    severity = (cvss_data.get("baseSeverity") or "").upper() or severity_from_score(score)
    descriptions = cve.get("descriptions") or []
    description = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")
    refs = [r.get("url", "") for r in cve.get("references") or [] if r.get("url")]
    return {
        "cve_id": cve.get("id", ""),
        "severity": normalize_severity(severity),
        "cvss_score": float(score) if score is not None else None,
        "vector_string": cvss_data.get("vectorString", ""),
        "description": description,
        "published": parse_dt(cve.get("published")),
        "last_modified": parse_dt(cve.get("lastModified")),
        "references": refs,
        "configurations": cve.get("configurations") or [],
        "raw": cve,
    }
