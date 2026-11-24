# API Documentation

Base URL: `http://127.0.0.1:8000/api/`

## Authentication

SupplyChainX uses Django session authentication for the UI and DRF token authentication for API clients.

```http
POST /api/auth/token/
Content-Type: application/x-www-form-urlencoded

username=analyst&password=your-password
```

Response:

```json
{"token": "9944b09199c62bcf9418ad846dd0e4bbdfc6ee4b"}
```

Send the token with every request:

```http
Authorization: Token 9944b09199c62bcf9418ad846dd0e4bbdfc6ee4b
```

## Conventions

- All list endpoints are paginated with 25 results per page (`count`, `next`, `previous`, `results`).
- All data is scoped to the authenticated user's organization memberships.
- Write operations require `OWNER`, `ADMIN`, or `MEMBER` role; viewers are read-only.
- Timestamps are ISO 8601 UTC.

## Resources

| Endpoint | Methods | Description |
|---|---|---|
| `/api/me/` | GET | Current user profile and role. |
| `/api/organizations/` | GET, POST | List/create organizations. |
| `/api/projects/` | GET, POST | List/create projects. |
| `/api/projects/{id}/upload/` | POST | Multipart ZIP upload; creates and dispatches a scan. |
| `/api/archives/` | GET | Uploaded archive metadata and SHA-256 digests. |
| `/api/scans/` | GET, POST | Scan history. |
| `/api/scans/{id}/queue/` | POST | Re-queue a pending/failed scan. |
| `/api/scans/{id}/summary/` | GET | Risk, health, graph, license and vulnerability summary. |
| `/api/dependencies/` | GET | Parsed components with purl, ecosystem and source file. |
| `/api/sboms/` | GET | CycloneDX documents with integrity hashes. |
| `/api/vulnerabilities/` | GET | Advisory findings with source attribution. |
| `/api/secret-findings/` | GET | Optional gitleaks results. |
| `/api/recommendations/` | GET | Prioritized, grounded remediation guidance. |
| `/api/licenses/` | GET | License classification and review flags. |
| `/api/reports/` | GET | Generated report metadata. |
| `/api/graph-metrics/` | GET | NetworkX graph aggregates and vulnerable paths. |
| `/api/graph-edges/` | GET | Persisted dependency edges. |
| `/api/risk-signals/` | GET | Heuristic supply-chain risk signals. |
| `/api/cve-records/` | GET | Normalized NVD records collected during scans. |
| `/api/intel-sources/` | GET | Health/status of OSV, NVD and optional local tools. |
| `/api/dashboard/summary/` | GET | Aggregate security posture for the current user. |
| `/api/schema/` | GET | OpenAPI 3 schema (JSON or browsable renderer). |

## Upload example

```powershell
curl -H "Authorization: Token <token>" -F "archive=@source.zip" http://127.0.0.1:8000/api/projects/1/upload/
```

The response is the newly created `Scan` object with `status: PENDING`. Poll `/api/scans/{id}/` or the HTML status endpoint until `COMPLETED`.

## Error responses

| Status | Meaning |
|---|---|
| 400 | Invalid archive or malformed request. |
| 403 | Authenticated but insufficient organization role. |
| 404 | Object not found or outside the user's tenant scope. |
| 409 | Scan cannot be queued in its current state. |

## Machine-readable schema

The OpenAPI document is generated from DRF viewsets and serializers. It includes operation IDs, parameters, request/response schemas and authentication requirements.

```powershell
curl -H "Authorization: Token <token>" http://127.0.0.1:8000/api/schema/ -o openapi.json
```
