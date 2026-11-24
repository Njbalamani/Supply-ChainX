# System Architecture

## Overview

SupplyChainX follows Django MVT architecture with a dedicated service layer for analysis and Celery for asynchronous work. The web tier and worker tier share PostgreSQL and Redis but have distinct responsibilities.

```text
Browser / API client
        |
        v
Django views + DRF viewsets  (MVT presentation layer)
        |
        v
Project services (upload validation, queue dispatch)
        |
        v
Celery task: run_scan(scan_id)
        |
        +--> dependency_parser (secure ZIP + manifests)
        +--> cve_intelligence  (OSV, NVD)
        +--> vulnerability_scanner (findings, pip-audit, gitleaks)
        +--> license_compliance
        +--> dependency_graph (NetworkX, risk signals)
        +--> sbom_generator (CycloneDX 1.5)
        +--> ai_recommendations (rule engine / optional LLM)
        |
        v
PostgreSQL --> reports/dashboard/API
```

## Application modules

| App | Responsibility |
|---|---|
| `accounts` | Custom user model with ADMIN / DEVELOPER / ANALYST roles. |
| `organizations` | Tenants, membership and role-based authorization helpers. |
| `projects` | Project registry, secure archive storage, scan lifecycle and views. |
| `dependency_parser` | ZIP validation, in-memory manifest reading and parsers for three ecosystems. |
| `sbom_generator` | Deterministic CycloneDX 1.5 JSON builder with SHA-256 integrity. |
| `vulnerability_scanner` | Advisory matching, optional local tools, secret findings and scan orchestration. |
| `cve_intelligence` | OSV/NVD HTTP clients, CVSS vector scoring, normalization and source health. |
| `dependency_graph` | NetworkX graph construction, metrics, vulnerable paths and risk heuristics. |
| `license_compliance` | SPDX classification, compatibility rules and review flags. |
| `ai_recommendations` | Grounded deterministic rule engine plus optional OpenAI summary. |
| `reports` | PDF, CSV, SBOM and risk-summary generation and downloads. |
| `dashboard` | Aggregate MVT dashboard and context processor. |

## Scan pipeline detail

1. **Upload** — `save_project_archive()` streams the uploaded file to a temporary file, validates it with `validate_zip()`, computes SHA-256, then stores it through Django's file storage under a UUID filename.
2. **Dispatch** — `dispatch_scan()` calls `run_scan.delay()`. If the broker is unavailable, a daemon thread runs the same task with connection cleanup.
3. **Parse** — `read_manifests()` reads only supported manifest files into memory; code files are never imported, evaluated or executed. Dependencies are de-duplicated and persisted.
4. **Advisory matching** — `osv_query_batch()` sends exact name/version/ecosystem tuples to OSV.dev. Details are fetched per advisory, normalized, and stored with source URLs and raw payloads. CVE aliases may be enriched from NVD.
5. **Optional tools** — `pip-audit` reads a generated requirements file; `gitleaks` scans a strictly extracted temporary copy of the source. Both are disabled by default and recorded when used.
6. **Analysis** — license records, graph metrics, vulnerable paths, risk signals and CycloneDX SBOM are generated from the same dependency snapshot.
7. **Recommendations** — rules derive upgrades from advisory `fixed` events; optional LLM output is limited to an executive summary grounded in stored facts.
8. **Finalization** — risk and health scores are stored, source status rows are captured, and the scan becomes `COMPLETED`. Exceptions roll back analysis writes via a savepoint and mark the scan `FAILED` with an error message.

## Security boundaries

- Uploaded archives are untrusted data. Path traversal, symlinks, encryption, oversized entries and compression bombs are rejected before storage.
- `pom.xml` uses `defusedxml`; DTD/ENTITY declarations are rejected.
- All outbound HTTP calls use bounded timeouts and explicit source status logging.
- CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy and Permissions-Policy are set by middleware.
- Role checks are enforced in MVT views, DRF permissions and queryset scoping.

## Scalability

- Celery workers can be scaled horizontally; scan work is routed to the `scans` queue.
- OSV queries are batched in groups of 100.
- Graph computation uses NetworkX in-process; very large dependency sets can be moved to a dedicated analysis worker without changing the API contract.
- PostgreSQL indexes cover scan status, dependency names, vulnerability severity and advisory IDs.
