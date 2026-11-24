# SupplyChainX

### AI-Powered Software Supply Chain Security Intelligence Platform

| | |
|---|---|
| **Repository** | [Njbalamani/Supply-ChainX](https://github.com/Njbalamani/Supply-ChainX) |
| **Project folder** | `supply-chain/` |
| **Author / Maintainer** | **Njbalamani** |
| **Version** | 1.0.0 |
| **License** | MIT (see `LICENSE`, copyright Njbalamani) |
| **Backend** | Python 3.12 · Django 6.1 · Django REST Framework 3.18 |
| **Database** | PostgreSQL 16 (production) · SQLite (local test override) |
| **Async** | Celery 5 · Redis 7 |
| **Intelligence** | OSV.dev · NVD · CycloneDX 1.5 · NetworkX |
| **Frontend** | Vanilla JS · Custom CSS · Three.js · Chart.js |

---

## Table of contents

1. [Executive summary](#1-executive-summary)
2. [Problem and solution](#2-problem-and-solution)
3. [Feature matrix](#3-feature-matrix)
4. [Technology stack](#4-technology-stack)
5. [Complete folder structure](#5-complete-folder-structure)
6. [Architecture diagrams](#6-architecture-diagrams)
7. [Application workflow](#7-application-workflow)
8. [Database connections and schema](#8-database-connections-and-schema)
9. [Environment configuration](#9-environment-configuration)
10. [Installation and startup](#10-installation-and-startup)
11. [Command reference](#11-command-reference)
12. [API reference](#12-api-reference)
13. [Security model](#13-security-model)
14. [Reports and artifacts](#14-reports-and-artifacts)
15. [Testing and verification](#15-testing-and-verification)
16. [Recommended reading order](#16-recommended-reading-order)
17. [Troubleshooting](#17-troubleshooting)
18. [Roadmap](#18-roadmap)
19. [Contributing](#19-contributing)
20. [Author and license](#20-author-and-license)

---

## 1. Executive summary

SupplyChainX turns an untrusted source-code ZIP into a verifiable supply-chain security assessment. It parses dependency manifests for Python, Node.js and Java/Maven, generates a CycloneDX 1.5 SBOM, queries real advisory databases, builds a transitive dependency graph, applies risk heuristics, produces grounded remediation guidance and exports audit-ready reports.

The platform is built with Django MVT, a service layer for analysis, DRF for machine access, PostgreSQL for persistence, Redis/Celery for background work and a custom premium UI with no Bootstrap dependency.

**Design principles**

- Real advisory data only. No invented CVEs or scores.
- Every finding carries source attribution.
- Uploaded code is never executed.
- Every tenant's data is isolated by membership.
- Analysis is reproducible from the stored archive and SBOM hashes.

---

## 2. Problem and solution

| Problem | SupplyChainX response |
|---|---|
| Teams do not know what is inside their dependencies. | Automatic manifest parsing and CycloneDX SBOM generation. |
| Advisory data is scattered across ecosystems. | OSV batch queries with optional NVD enrichment in one normalized model. |
| Direct vulnerabilities hide transitive risk. | NetworkX graph paths, hubs, concentration, depth and cycle metrics. |
| Scan results are hard to explain to auditors. | PDF, CSV, JSON, SBOM and graph exports with checksums. |
| Uploaded archives may be malicious. | Strict ZIP validation, safe XML parsing, size/ratio caps and no code execution. |
| Security tools are optional and inconsistent. | Source status records show exactly which tool/advisory source produced each result. |
| Dashboards are often cosmetic. | Charts and 3D graph are generated from persisted scan facts. |

---

## 3. Feature matrix

| Module | Capabilities | Primary files |
|---|---|---|
| `accounts` | Custom user, roles `ADMIN`, `DEVELOPER`, `ANALYST`, auth pages | `accounts/models.py`, `accounts/forms.py`, `accounts/views.py` |
| `organizations` | Tenants, memberships, owner/admin/member/viewer permissions | `organizations/models.py`, `organizations/permissions.py`, `organizations/api_permissions.py` |
| `projects` | Projects, secure archive upload, scan history, MVT pages | `projects/models.py`, `projects/services.py`, `projects/views.py` |
| `dependency_parser` | ZIP validation, manifest readers, purl generation | `dependency_parser/archive.py`, `dependency_parser/parsers.py`, `dependency_parser/purl.py` |
| `sbom_generator` | CycloneDX 1.5 JSON, SHA-256 integrity | `sbom_generator/service.py` |
| `cve_intelligence` | OSV/NVD clients, CVSS scoring, normalization, source health | `cve_intelligence/clients.py`, `cve_intelligence/models.py` |
| `vulnerability_scanner` | Finding persistence, pip-audit, gitleaks, orchestration | `vulnerability_scanner/tasks.py`, `vulnerability_scanner/services.py` |
| `dependency_graph` | Graph metrics, vulnerable paths, risk signals | `dependency_graph/service.py`, `dependency_graph/risk.py` |
| `license_compliance` | SPDX classification, conflicts, review flags | `license_compliance/service.py` |
| `ai_recommendations` | Rule engine, optional grounded OpenAI summary | `ai_recommendations/service.py` |
| `reports` | PDF, CSV, SBOM, risk and graph downloads | `reports/services.py`, `reports/views.py` |
| `dashboard` | Aggregate posture, chart JSON, context processor | `dashboard/views.py`, `dashboard/context_processors.py` |
| `config` | Settings, URLs, Celery, DRF, security middleware | `config/settings.py`, `config/api_urls.py`, `config/middleware.py` |
| `docs` | In-app documentation pages and Markdown references | `docs/`, `templates/docs/` |
| `tests` | Parser, archive, pipeline, view and API tests | `tests/test_parsers.py`, `tests/test_pipeline.py`, `tests/test_views.py` |

---

## 4. Technology stack

| Layer | Technology | Why it is used |
|---|---|---|
| Language | Python 3.12 | Modern typing, standard library strength. |
| Web framework | Django 6.1 | MVT, ORM, auth, admin, migrations. |
| API | Django REST Framework 3.18 | Viewsets, token auth, schema, throttling. |
| Primary DB | PostgreSQL 16 | Relational integrity, indexes, concurrency. |
| Test DB | SQLite | Fast offline verification without a server. |
| Task queue | Celery 5 | Durable background scan execution. |
| Broker/backend | Redis 7 | Queue and result storage. |
| Graph engine | NetworkX 3.6 | Path, centrality and transitive analysis. |
| SBOM | CycloneDX 1.5 JSON | Machine-readable component inventory. |
| Advisory sources | OSV.dev, NVD | Authoritative vulnerability data. |
| Optional tools | pip-audit, gitleaks | Secondary dependency and secret checks. |
| XML safety | defusedxml | DTD/ENTITY attack prevention. |
| PDF | ReportLab | Deterministic report generation. |
| Frontend | HTML, CSS, JavaScript | Custom UI; no Bootstrap. |
| Visualization | Three.js, Chart.js | 3D dependency graph and metrics charts. |
| Static serving | WhiteNoise | Production static-file delivery. |
| Process manager | Gunicorn | Production WSGI server. |
| Containers | Docker Compose | Reproducible multi-service deployment. |

---

## 5. Complete folder structure

```text
Supply-ChainX/
├── README.md                          # Root repository guide
└── supply-chain/                      # THIS PROJECT
    ├── manage.py                      # Django management entry point
    ├── requirements.txt               # Pinned Python dependencies
    ├── .env.example                   # Environment variable template
    ├── .gitignore                     # Ignored files and folders
    ├── .dockerignore                  # Docker build exclusions
    ├── Dockerfile                     # Application image
    ├── docker-compose.yml             # web + worker + db + redis
    ├── LICENSE                        # MIT License, copyright Njbalamani
    ├── README.md                      # This document
    │
    ├── config/                        # Django project configuration
    │   ├── __init__.py
    │   ├── settings.py                # DB, security, Celery, scan settings
    │   ├── urls.py                    # Root URL configuration
    │   ├── api_urls.py                # DRF router, token, schema, dashboard API
    │   ├── api_views.py               # Custom API views
    │   ├── viewsets.py                # Organization-scoped viewsets
    │   ├── serializers.py             # DRF serializers
    │   ├── middleware.py              # CSP and security headers
    │   ├── celery.py                  # Celery application
    │   ├── constants.py               # Shared constants
    │   ├── wsgi.py                    # WSGI deployment entry point
    │   └── asgi.py                    # ASGI deployment entry point
    │
    ├── accounts/                      # Identity and roles
    │   ├── __init__.py
    │   ├── models.py                  # User(AbstractUser), Role
    │   ├── forms.py                   # Login/signup forms
    │   ├── views.py                   # Authentication views
    │   ├── urls.py
    │   ├── admin.py
    │   ├── apps.py
    │   └── migrations/
    │       ├── __init__.py
    │       └── 0001_initial.py
    │
    ├── organizations/                 # Tenancy and access control
    │   ├── __init__.py
    │   ├── models.py                  # Organization, OrganizationMember
    │   ├── permissions.py             # MVT permission helpers
    │   ├── api_permissions.py         # DRF permission classes
    │   ├── views.py
    │   ├── urls.py
    │   ├── admin.py
    │   ├── apps.py
    │   └── migrations/
    │       ├── __init__.py
    │       └── 0001_initial.py
    │
    ├── projects/                      # Project/archive/scan lifecycle
    │   ├── __init__.py
    │   ├── models.py                  # Project, ProjectArchive, Scan
    │   ├── services.py                # Secure save + scan dispatch
    │   ├── storage.py                 # Upload path handling
    │   ├── tasks.py                   # Scan status helpers
    │   ├── forms.py
    │   ├── permissions.py
    │   ├── views.py
    │   ├── urls.py
    │   ├── scan_urls.py
    │   ├── admin.py
    │   ├── apps.py
    │   └── migrations/
    │       ├── __init__.py
    │       └── 0001_initial.py
    │
    ├── dependency_parser/             # Untrusted archive handling and parsing
    │   ├── __init__.py
    │   ├── archive.py                 # ZIP validation, safe read/extract
    │   ├── parsers.py                 # requirements, package.json, lock, yarn, pom
    │   ├── purl.py                    # Package URL generation
    │   ├── models.py                  # ParsedDependency
    │   ├── admin.py
    │   ├── apps.py
    │   └── migrations/
    │       ├── __init__.py
    │       └── 0001_initial.py
    │
    ├── sbom_generator/                # CycloneDX generation
    │   ├── __init__.py
    │   ├── service.py                 # build_cyclonedx_document, generate_sbom
    │   ├── models.py                  # SBOM
    │   ├── admin.py
    │   ├── apps.py
    │   └── migrations/
    │       ├── __init__.py
    │       └── 0001_initial.py
    │
    ├── cve_intelligence/              # Advisory clients and source health
    │   ├── __init__.py
    │   ├── clients.py                 # osv_query_batch, osv_fetch_vuln, nvd_fetch_cve
    │   ├── models.py                  # CVERecord, IntelSourceStatus
    │   ├── admin.py
    │   ├── apps.py
    │   └── migrations/
    │       ├── __init__.py
    │       └── 0001_initial.py
    │
    ├── vulnerability_scanner/         # Findings and orchestration
    │   ├── __init__.py
    │   ├── models.py                  # Vulnerability, SecretFinding
    │   ├── services.py                # Finding persistence, pip-audit, gitleaks
    │   ├── tasks.py                   # run_scan pipeline
    │   ├── admin.py
    │   ├── apps.py
    │   └── migrations/
    │       ├── __init__.py
    │       └── 0001_initial.py
    │
    ├── dependency_graph/              # NetworkX analysis
    │   ├── __init__.py
    │   ├── service.py                 # Graph construction and metrics
    │   ├── risk.py                    # Risk signals and update history
    │   ├── models.py                  # GraphMetric, DependencyEdge, RiskSignal
    │   ├── admin.py
    │   ├── apps.py
    │   └── migrations/
    │       ├── __init__.py
    │       └── 0001_initial.py
    │
    ├── license_compliance/            # License classification
    │   ├── __init__.py
    │   ├── service.py                 # SPDX classification and conflicts
    │   ├── models.py                  # LicenseRecord, LicenseReport
    │   ├── admin.py
    │   ├── apps.py
    │   └── migrations/
    │       ├── __init__.py
    │       └── 0001_initial.py
    │
    ├── ai_recommendations/            # Grounded remediation guidance
    │   ├── __init__.py
    │   ├── service.py                 # Rule engine + optional OpenAI summary
    │   ├── models.py                  # Recommendation
    │   ├── admin.py
    │   ├── apps.py
    │   └── migrations/
    │       ├── __init__.py
    │       └── 0001_initial.py
    │
    ├── reports/                       # Export layer
    │   ├── __init__.py
    │   ├── services.py                # PDF, CSV, risk JSON builders
    │   ├── views.py                   # Download endpoints
    │   ├── models.py                  # Report
    │   ├── urls.py
    │   ├── admin.py
    │   ├── apps.py
    │   └── migrations/
    │       ├── __init__.py
    │       └── 0001_initial.py
    │
    ├── dashboard/                     # MVT dashboard
    │   ├── __init__.py
    │   ├── views.py                   # Dashboard and chart JSON
    │   ├── context_processors.py      # Platform-wide template context
    │   ├── urls.py
    │   ├── apps.py
    │   └── migrations/
    │       └── __init__.py
    │
    ├── docs/                          # In-app docs + Markdown references
    │   ├── __init__.py
    │   ├── urls.py
    │   ├── views.py
    │   ├── API.md
    │   ├── ARCHITECTURE.md
    │   ├── ER_DIAGRAM.md
    │   └── DEPLOYMENT.md
    │
    ├── templates/                     # Server-rendered UI
    │   ├── base.html                  # Global shell, nav, glass layout
    │   ├── accounts/
    │   │   ├── login.html
    │   │   └── signup.html
    │   ├── dashboard/
    │   │   └── index.html             # Charts and posture cards
    │   ├── organizations/
    │   │   ├── list.html
    │   │   ├── detail.html
    │   │   └── create.html
    │   ├── projects/
    │   │   ├── list.html
    │   │   ├── detail.html
    │   │   └── create.html
    │   ├── scans/
    │   │   └── detail.html            # Findings, graph stage, downloads
    │   └── docs/
    │       ├── index.html
    │       ├── api.html
    │       ├── architecture.html
    │       └── er_diagram.html
    │
    ├── static/                        # Custom frontend assets
    │   ├── css/
    │   │   └── main.css               # Midnight/gold/silver glass design
    │   ├── js/
    │   │   └── app.js                 # Chart.js, Three.js, polling, filters
    │   └── vendor/
    │       ├── chart.umd.min.js
    │       ├── chart.umd.js.map
    │       └── three.min.js
    │
    ├── media/                         # Runtime data (git-kept folders only)
    │   ├── archives/
    │   │   └── .gitkeep
    │   └── reports/
    │       └── .gitkeep
    │
    └── tests/                         # Verification suite
        ├── __init__.py
        ├── test_parsers.py            # Parsers + archive security
        ├── test_pipeline.py           # Mocked OSV full pipeline + SBOM + PDF
        ├── test_views.py              # HTML, API, scoping, schema, upload
        └── fixtures/
            ├── sample-requirements.txt
            ├── sample-package.json
            ├── sample-package-lock.json
            └── sample-pom.xml
```

---

## 6. Architecture diagrams

### 6.1 System context

```mermaid
flowchart LR
    User["Security Analyst / Developer / Admin"]
    API["External API Client"]
    UI["Django MVT UI"]
    DRF["DRF REST API"]
    Web["Gunicorn Web Service"]
    Worker["Celery Scan Worker"]
    PG["PostgreSQL 16"]
    Redis["Redis 7"]
    OSV["OSV.dev API"]
    NVD["NVD CVE API 2.0"]
    LLM["Optional OpenAI API"]
    Tools["Optional pip-audit / gitleaks"]
    Files["media/ archives + reports"]

    User --> UI
    API --> DRF
    UI --> Web
    DRF --> Web
    Web --> PG
    Web --> Redis
    Web --> Files
    Worker --> PG
    Worker --> Redis
    Worker --> Files
    Worker --> OSV
    Worker --> NVD
    Worker --> LLM
    Worker --> Tools
```

### 6.2 Layered application architecture

```mermaid
flowchart TD
    P["Presentation Layer<br/>templates + static/css + static/js"]
    V["View / Viewset Layer<br/>MVT views + DRF viewsets + serializers"]
    S["Service Layer<br/>services.py + tasks.py + clients.py"]
    D["Domain Models / ORM<br/>12 Django apps"]
    DB[("PostgreSQL")]
    Q[("Redis + Celery")]
    X["External Intelligence<br/>OSV, NVD, LLM, CLI tools"]

    P --> V --> S --> D --> DB
    S --> Q
    Q --> S
    S --> X
```

### 6.3 Scan pipeline sequence

```mermaid
sequenceDiagram
    actor U as User / API Client
    participant W as Django Web
    participant DB as PostgreSQL
    participant Q as Redis / Celery
    participant T as Scan Worker
    participant P as dependency_parser
    participant O as OSV / NVD
    participant G as Graph + SBOM + Reports

    U->>W: Upload source.zip
    W->>W: Validate ZIP structure and limits
    W->>DB: Create ProjectArchive + Scan(PENDING)
    W->>Q: run_scan.delay(scan_id)
    W-->>U: Scan ID + PENDING status
    Q->>T: Deliver task
    T->>DB: Scan -> RUNNING
    T->>P: Read manifests in memory
    P-->>T: Normalized dependency list
    T->>DB: Persist ParsedDependency rows
    T->>O: OSV batch query + detail fetch
    O-->>T: Advisory payloads
    T->>DB: Persist Vulnerability + CVERecord + source status
    T->>G: License, graph, risk, SBOM, recommendations
    G-->>T: Metrics + document + guidance
    T->>DB: Persist analysis + scores
    T->>DB: Scan -> COMPLETED
    U->>W: Poll status / open assessment
```

### 6.4 Scan state machine

```mermaid
stateDiagram-v2
    [*] --> PENDING: Upload accepted
    PENDING --> RUNNING: Worker starts
    PENDING --> FAILED: Dispatch error
    RUNNING --> COMPLETED: Analysis finished
    RUNNING --> FAILED: Pipeline exception
    FAILED --> PENDING: Manual re-queue
    COMPLETED --> PENDING: New scan created
    COMPLETED --> [*]
```

### 6.5 Database entity relationship

```mermaid
erDiagram
    USER ||--o{ ORGANIZATION : owns
    USER ||--o{ ORGANIZATION_MEMBER : has
    ORGANIZATION ||--o{ ORGANIZATION_MEMBER : contains
    ORGANIZATION ||--o{ PROJECT : contains
    USER ||--o{ PROJECT : creates
    USER ||--o{ SCAN : triggers
    PROJECT ||--o{ PROJECT_ARCHIVE : stores
    PROJECT ||--o{ SCAN : has
    PROJECT_ARCHIVE ||--o{ SCAN : backs

    SCAN ||--o{ PARSED_DEPENDENCY : contains
    SCAN ||--o{ VULNERABILITY : finds
    PARSED_DEPENDENCY ||--o{ VULNERABILITY : matched_by
    SCAN ||--|| SBOM : generates
    SCAN ||--|| GRAPH_METRIC : measures
    SCAN ||--o{ DEPENDENCY_EDGE : links
    SCAN ||--o{ RISK_SIGNAL : flags
    RISK_SIGNAL }o--|| PARSED_DEPENDENCY : about
    SCAN ||--o{ LICENSE_RECORD : classifies
    LICENSE_RECORD }o--|| PARSED_DEPENDENCY : about
    SCAN ||--|| LICENSE_REPORT : summarizes
    SCAN ||--o{ RECOMMENDATION : recommends
    RECOMMENDATION }o--o| VULNERABILITY : addresses
    RECOMMENDATION }o--o| PARSED_DEPENDENCY : targets
    SCAN ||--o{ SECRET_FINDING : detects
    SCAN ||--o{ REPORT : exports
```

### 6.6 Analysis fan-out

```mermaid
flowchart TD
    D["ParsedDependency set"]
    D --> OSV["OSV vulnerability matching"]
    D --> LIC["SPDX license classification"]
    D --> GR["NetworkX graph build"]
    D --> SBOM["CycloneDX component list"]
    GR --> MET["Hubs / depth / cycles / concentration"]
    GR --> VP["Vulnerable paths"]
    OSV --> RISK["Risk score + health score"]
    MET --> RISK
    VP --> RISK
    LIC --> RISK
    RISK --> REC["Rule-engine recommendations"]
    RISK --> REP["PDF / CSV / JSON reports"]
    SBOM --> REP
```

### 6.7 Container deployment

```mermaid
flowchart TB
    Client["Browser / API client"]
    Proxy["Reverse proxy + TLS"]
    subgraph Compose["Docker Compose"]
        Web["web: Gunicorn + Django"]
        Worker["worker: Celery"]
        DB[("db: PostgreSQL 16")]
        Cache[("redis: Redis 7")]
        Vol1[("postgres_data")]
        Vol2[("static_data")]
        Vol3[("media_data")]
    end

    Client --> Proxy --> Web
    Web --> DB
    Web --> Cache
    Worker --> DB
    Worker --> Cache
    DB --> Vol1
    Web --> Vol2
    Web --> Vol3
    Worker --> Vol3
```

---

## 7. Application workflow

### 7.1 User workflow

| Step | Actor | Action | System result |
|---:|---|---|---|
| 1 | Admin | Create organization | Tenant row + admin membership created. |
| 2 | User | Register or sign in | Custom `User` authenticated; role assigned. |
| 3 | Member | Create project | Project scoped to organization. |
| 4 | Member | Upload `source.zip` | Archive validated; SHA-256 stored; `Scan(PENDING)` created. |
| 5 | Worker | Execute `run_scan` | Status moves to `RUNNING`. |
| 6 | Worker | Parse manifests | `ParsedDependency` rows created. |
| 7 | Worker | Query OSV/NVD | Vulnerabilities, CVE records, source statuses stored. |
| 8 | Worker | Analyze | License, graph, risk, SBOM and recommendations stored. |
| 9 | Worker | Finalize | Scores saved; status becomes `COMPLETED`. |
| 10 | Analyst | Open scan detail | Charts, 3D graph, findings and downloads rendered. |
| 11 | Auditor | Export report | PDF/CSV/SBOM/risk/graph files generated and checksummed. |

### 7.2 Pipeline execution order

```text
1. upload archive
2. validate ZIP (path, symlink, encryption, size, count, ratio)
3. compute SHA-256 and store archive
4. create Scan(PENDING) and dispatch Celery task
5. set Scan(RUNNING)
6. read supported manifests in memory
7. parse + normalize dependencies (name, version, ecosystem, purl)
8. query OSV batch and fetch advisory details
9. optionally enrich CVE aliases from NVD
10. persist vulnerabilities and source status
11. optionally run pip-audit and gitleaks
12. classify licenses
13. build NetworkX graph and metrics
14. derive risk signals and scores
15. generate CycloneDX SBOM
16. build grounded recommendations
17. save report metadata
18. set Scan(COMPLETED)
19. on exception: rollback analysis, set Scan(FAILED) with error text
```

### 7.3 Permission workflow

| Role | View projects | Create projects | Upload scans | Manage org | Manage users |
|---|---:|---:|---:|---:|---:|
| Viewer | Yes | No | No | No | No |
| Member | Yes | Yes | Yes | No | No |
| Admin | Yes | Yes | Yes | Yes | Yes |
| Owner | Yes | Yes | Yes | Yes | Yes |
| `ADMIN` platform role | Yes | Yes | Yes | Yes | Yes |

---

## 8. Database connections and schema

### 8.1 Connection resolution

Django resolves the active database in `config/settings.py` in this order:

```mermaid
flowchart TD
    A["Start Django"] --> B{"DATABASE_URL set?"}
    B -->|Yes| C["Parse URL with urllib.parse"]
    C --> D["ENGINE = django.db.backends.postgresql"]
    D --> E["NAME / USER / PASSWORD / HOST / PORT from URL"]
    B -->|No| F{"DB_ENGINE set?"}
    F -->|sqlite or sqlite3| G["ENGINE = django.db.backends.sqlite3"]
    F -->|postgresql/default| H["ENGINE = django.db.backends.postgresql"]
    G --> I["NAME from DB_NAME or BASE_DIR/db.sqlite3"]
    H --> J["NAME/USER/PASSWORD/HOST/PORT from DB_* vars"]
    E --> K["Active DATABASES['default']"]
    I --> K
    J --> K
```

### 8.2 Production PostgreSQL connection

```env
DATABASE_URL=postgresql://supplychainx:strong-password@db:5432/supplychainx
DB_ENGINE=django.db.backends.postgresql
```

When `DATABASE_URL` exists it takes precedence over the individual `DB_*` variables. Extra query parameters are passed to `OPTIONS`.

Example with SSL:

```env
DATABASE_URL=postgresql://supplychainx:strong-password@db.example.com:5432/supplychainx?sslmode=require
```

Create the database manually if not using Compose:

```sql
CREATE USER supplychainx WITH PASSWORD 'strong-password';
CREATE DATABASE supplychainx OWNER supplychainx;
GRANT ALL PRIVILEGES ON DATABASE supplychainx TO supplychainx;
```

### 8.3 Local SQLite connection

```powershell
$env:DB_ENGINE='django.db.backends.sqlite3'
```

Or in `.env`:

```env
DB_ENGINE=django.db.backends.sqlite3
DB_NAME=db.sqlite3
```

SQLite is intended for tests and offline demos only. Production uses PostgreSQL.

### 8.4 Connection and storage settings

| Setting | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | unset | Full PostgreSQL DSN; highest priority. |
| `DB_ENGINE` | `django.db.backends.postgresql` | Django database backend. |
| `DB_NAME` | `supplychainx` / `BASE_DIR/db.sqlite3` | Database name/path. |
| `DB_USER` | `supplychainx` | Database user. |
| `DB_PASSWORD` | `supplychainx` | Database password. |
| `DB_HOST` | `localhost` | Database host. |
| `DB_PORT` | `5432` | Database port. |
| `FILE_UPLOAD_MAX_MEMORY_SIZE` | 4 MB | In-memory upload threshold. |
| `DATA_UPLOAD_MAX_MEMORY_SIZE` | 32 MB | Request body cap. |
| `MEDIA_ROOT` | `BASE_DIR/media` | Archives and reports on disk. |
| `STATIC_ROOT` | `BASE_DIR/staticfiles` | Collected static assets. |

### 8.5 Logical table order

Create/read tables in this dependency order. Migrations already encode it.

| Order | App | Model / table | Purpose | Key relations |
|---:|---|---|---|---|
| 1 | `accounts` | `User` | Identity and platform role | Referenced by all ownership fields. |
| 2 | `organizations` | `Organization` | Tenant root | Owned by `User`. |
| 3 | `organizations` | `OrganizationMember` | Membership + tenant role | `Organization` + `User`. |
| 4 | `projects` | `Project` | Assessment target | `Organization` + `User`. |
| 5 | `projects` | `ProjectArchive` | Immutable uploaded ZIP + hash | `Project`. |
| 6 | `projects` | `Scan` | One assessment run | `Project`, `ProjectArchive`, `User`. |
| 7 | `dependency_parser` | `ParsedDependency` | Component inventory | `Scan`. |
| 8 | `cve_intelligence` | `CVERecord` | Normalized NVD cache | Global. |
| 9 | `cve_intelligence` | `IntelSourceStatus` | Source health per scan | `Scan`. |
| 10 | `vulnerability_scanner` | `Vulnerability` | Advisory finding | `Scan`, `ParsedDependency`. |
| 11 | `vulnerability_scanner` | `SecretFinding` | gitleaks result | `Scan`. |
| 12 | `license_compliance` | `LicenseRecord` | Component license | `Scan`, `ParsedDependency`. |
| 13 | `license_compliance` | `LicenseReport` | Aggregate license summary | `Scan`. |
| 14 | `dependency_graph` | `DependencyEdge` | Directed graph edge | `Scan`. |
| 15 | `dependency_graph` | `GraphMetric` | Metrics snapshot | `Scan`. |
| 16 | `dependency_graph` | `RiskSignal` | Heuristic warning | `Scan`, `ParsedDependency`. |
| 17 | `sbom_generator` | `SBOM` | CycloneDX document + checksum | `Scan`. |
| 18 | `ai_recommendations` | `Recommendation` | Prioritized guidance | `Scan`, optional `Vulnerability`, optional `ParsedDependency`. |
| 19 | `reports` | `Report` | Generated artifact metadata + checksum | `Scan`. |

### 8.6 Important fields

| Model | Important fields |
|---|---|
| `User` | `username`, `email`, `role` (`ADMIN`/`DEVELOPER`/`ANALYST`). |
| `Organization` | `name`, `slug`, `owner`, `created_at`. |
| `OrganizationMember` | `organization`, `user`, `role` (`OWNER`/`ADMIN`/`MEMBER`/`VIEWER`). |
| `Project` | `organization`, `name`, `ecosystem`, `description`, `created_by`. |
| `ProjectArchive` | `project`, `file`, `sha256`, `original_name`, `size_bytes`, `uploaded_by`. |
| `Scan` | `project`, `archive`, `status`, `risk_score`, `health_score`, `error`, `sources_version`. |
| `ParsedDependency` | `scan`, `name`, `version`, `ecosystem`, `purl`, `source_file`, `is_direct`. |
| `Vulnerability` | `scan`, `dependency`, `vuln_id`, `aliases`, `severity`, `cvss_score`, `fixed_versions`, `source`, `source_url`, `raw`. |
| `CVERecord` | `cve_id`, `severity`, `cvss_score`, `vector`, `published`, `raw`. |
| `IntelSourceStatus` | `name`, `status`, `detail`, `last_attempt`, `scan`. |
| `SBOM` | `scan`, `document`, `sha256`, `format`, `spec_version`, `generated_at`. |
| `GraphMetric` | `scan`, `node_count`, `edge_count`, `vulnerable_paths`, `max_depth`, `centrality`, `cycle_count`. |
| `RiskSignal` | `scan`, `dependency`, `signal_type`, `severity`, `message`, `evidence`. |
| `LicenseRecord` | `scan`, `dependency`, `license_id`, `name`, `category`, `conflict`, `needs_review`. |
| `Recommendation` | `scan`, `type`, `priority`, `title`, `detail`, `evidence`, `vulnerability`, `dependency`. |
| `Report` | `scan`, `report_type`, `file`, `sha256`, `generated_at`. |

### 8.7 Useful database commands

```powershell
python manage.py makemigrations
python manage.py migrate
python manage.py showmigrations
python manage.py dbshell
python manage.py dumpdata --indent 2 > backup.json
python manage.py loaddata backup.json
python manage.py shell -c "from django.db import connection; print(connection.vendor)"
```

---

## 9. Environment configuration

Copy the template first:

```powershell
copy .env.example .env
```

### 9.1 Core settings

| Variable | Example | Required | Description |
|---|---|---:|---|
| `DJANGO_SECRET_KEY` | long random string | Production | Django signing key. |
| `DJANGO_DEBUG` | `False` | Yes | Debug mode; must be false in production. |
| `DJANGO_ALLOWED_HOSTS` | `localhost,127.0.0.1,scx.example.com` | Production | Comma-separated hostnames. |
| `DATABASE_URL` | `postgresql://user:pass@db:5432/supplychainx` | Production | Preferred DB connection string. |
| `DB_ENGINE` | `django.db.backends.postgresql` | No | Backend when no DSN. |
| `DB_NAME` | `supplychainx` | No | DB name/path. |
| `DB_USER` | `supplychainx` | No | DB user. |
| `DB_PASSWORD` | `strong-password` | No | DB password. |
| `DB_HOST` | `db` | No | DB host. |
| `DB_PORT` | `5432` | No | DB port. |

### 9.2 Queue settings

| Variable | Example | Description |
|---|---|---|
| `CELERY_BROKER_URL` | `redis://redis:6379/0` | Task broker. |
| `CELERY_RESULT_BACKEND` | `redis://redis:6379/1` | Result storage. |
| `CELERY_TASK_ALWAYS_EAGER` | `False` | When true, tasks run in-process (local testing). |

### 9.3 Intelligence settings

| Variable | Example | Description |
|---|---|---|
| `OSV_QUERY_URL` | `https://api.osv.dev/v1/querybatch` | Batch advisory endpoint. |
| `OSV_VULN_URL` | `https://api.osv.dev/v1/vulns/{vuln_id}` | Advisory detail endpoint. |
| `NVD_CVE_URL` | `https://services.nvd.nist.gov/rest/json/cves/2.0` | NVD endpoint. |
| `NVD_API_KEY` | empty | Optional NVD key. |
| `ENABLE_NVD_ENRICHMENT` | `True` | Enrich OSV aliases with NVD. |
| `SCAN_HTTP_TIMEOUT` | `15` | Outbound HTTP timeout seconds. |
| `ENABLE_PIP_AUDIT` | `False` | Enable secondary Python audit. |
| `PIP_AUDIT_PATH` | `pip-audit` | Binary path. |
| `ENABLE_GITLEAKS` | `False` | Enable secret scanning. |
| `GITLEAKS_PATH` | `gitleaks` | Binary path. |
| `AI_PROVIDER` | `rule_engine` | `rule_engine` or `openai`. |
| `OPENAI_API_KEY` | empty | Required only for OpenAI. |
| `OPENAI_MODEL` | `gpt-4o-mini` | Optional LLM model. |

### 9.4 Scan safety settings

| Variable | Default | Meaning |
|---|---:|---|
| `SCAN_MAX_ZIP_BYTES` | `104857600` | 100 MB compressed upload cap. |
| `SCAN_MAX_UNCOMPRESSED_BYTES` | `262144000` | 250 MB uncompressed cap. |
| `SCAN_MAX_FILES` | `5000` | Maximum archive entries. |
| `SCAN_MAX_FILE_BYTES` | `52428800` | 50 MB per-file cap. |
| `SCAN_COMPRESSION_RATIO_LIMIT` | `200` | Compression-bomb ratio cap. |
| `SCAN_TIMEOUT_SECONDS` | `300` | Scan timeout. |
| `API_RATE_LIMIT` | `1000/hour` | DRF user throttle. |
| `LOG_LEVEL` | `INFO` | Root and `supplychainx` logger level. |

### 9.5 Transport security settings

| Variable | Development | Production |
|---|---:|---:|
| `SECURE_SSL_REDIRECT` | `False` | `True` |
| `SESSION_COOKIE_SECURE` | `False` | `True` |
| `CSRF_COOKIE_SECURE` | `False` | `True` |
| `SECURE_HSTS_SECONDS` | `0` | `31536000` after TLS verified |

---

## 10. Installation and startup

### 10.1 Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Python | 3.12+ | Required for local/Docker builds. |
| pip | 23+ | Dependency installer. |
| PostgreSQL | 14+ | 16 recommended. |
| Redis | 6+ | 7 recommended. |
| Git | any recent | Clone repository. |
| Docker Desktop | latest | Only for container path. |
| pip-audit | optional | Secondary Python audit. |
| gitleaks | optional | Secret detection. |

### 10.2 Windows PowerShell (local development)

```powershell
git clone https://github.com/Njbalamani/Supply-ChainX.git
cd Supply-ChainX\supply-chain

python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

copy .env.example .env
notepad .env
```

Set local test mode in `.env`:

```env
DJANGO_DEBUG=True
DB_ENGINE=django.db.backends.sqlite3
CELERY_TASK_ALWAYS_EAGER=True
```

Initialize:

```powershell
python manage.py migrate
python manage.py createsuperuser
python manage.py collectstatic --noinput
python manage.py runserver
```

Open:

- Application: `http://127.0.0.1:8000/`
- Admin: `http://127.0.0.1:8000/admin/`
- API schema: `http://127.0.0.1:8000/api/schema/`
- In-app docs: `http://127.0.0.1:8000/docs/`

### 10.3 Linux / macOS (local development)

```bash
git clone https://github.com/Njbalamani/Supply-ChainX.git
cd Supply-ChainX/supply-chain

python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
python manage.py migrate
python manage.py createsuperuser
python manage.py collectstatic --noinput
python manage.py runserver
```

### 10.4 Docker Compose (recommended full stack)

```powershell
cd Supply-ChainX\supply-chain
copy .env.example .env
docker compose up --build -d
docker compose exec web python manage.py createsuperuser
```

Services started:

| Service | Image/Build | Port | Role |
|---|---|---:|---|
| `web` | local `Dockerfile` | `8000` | Django + Gunicorn. |
| `worker` | local `Dockerfile` | internal | Celery scan worker. |
| `db` | `postgres:16-alpine` | internal | PostgreSQL primary store. |
| `redis` | `redis:7-alpine` | internal | Celery broker/result backend. |

Useful Compose commands:

```powershell
docker compose ps
docker compose logs -f web
docker compose logs -f worker
docker compose restart web worker
docker compose down
docker compose down -v
```

### 10.5 First scan checklist

1. Sign in and create an organization.
2. Open **Projects** and create a project.
3. Build a ZIP containing one or more supported manifests.
4. Upload it from the project detail page.
5. Watch status change `PENDING` to `RUNNING` to `COMPLETED`.
6. Open the scan detail page to review findings, graph and downloads.

Supported manifests:

| Ecosystem | Files |
|---|---|
| Python | `requirements.txt`, `requirements-*.txt`, `*-requirements.txt` |
| Node.js | `package.json`, `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock` |
| Java / Maven | `pom.xml` |

---

## 11. Command reference

### 11.1 Django management

| Command | Purpose |
|---|---|
| `python manage.py check` | Run system checks. |
| `python manage.py check --deploy` | Production security checks. |
| `python manage.py makemigrations` | Generate migrations after model changes. |
| `python manage.py migrate` | Apply migrations. |
| `python manage.py showmigrations` | Show migration state. |
| `python manage.py createsuperuser` | Create admin account. |
| `python manage.py changepassword <user>` | Reset a user password. |
| `python manage.py collectstatic --noinput` | Collect static files. |
| `python manage.py dbshell` | Open database shell. |
| `python manage.py shell` | Open Django shell. |
| `python manage.py runserver` | Start development server. |
| `python manage.py test tests -v 2` | Run full test suite. |
| `python manage.py test tests.test_parsers -v 2` | Parser/archive tests only. |
| `python manage.py test tests.test_pipeline -v 2` | Pipeline/SBOM/PDF tests only. |
| `python manage.py test tests.test_views -v 2` | HTML/API/schema tests only. |

### 11.2 Celery and services

| Command | Purpose |
|---|---|
| `celery -A config worker -l info` | Start default worker. |
| `celery -A config worker -l info -Q celery,scans,maintenance --concurrency=2` | Start production-style worker. |
| `celery -A config inspect active` | Inspect running tasks. |
| `celery -A config inspect registered` | List registered tasks. |
| `gunicorn config.wsgi:application --bind 0.0.0.0:8000 --workers 3 --timeout 120` | Serve production WSGI app. |
| `docker compose up --build -d` | Start all containers. |
| `docker compose exec worker celery -A config inspect active` | Inspect container worker. |

### 11.3 Environment-specific test command

```powershell
$env:DB_ENGINE='django.db.backends.sqlite3'
python manage.py test tests -v 2
```

Optional live OSV test:

```powershell
$env:RUN_LIVE_OSV_TEST='1'
python manage.py test tests.test_views.LiveOSVIntegrationTests -v 2
```

---

## 12. API reference

Base URL: `http://127.0.0.1:8000/api/`

### 12.1 Authentication

```powershell
curl -X POST http://127.0.0.1:8000/api/auth/token/ -d "username=admin&password=your-password"
```

Use the token:

```powershell
curl -H "Authorization: Token <token>" http://127.0.0.1:8000/api/projects/
```

Upload a scan:

```powershell
curl -H "Authorization: Token <token>" -F "archive=@source.zip" http://127.0.0.1:8000/api/projects/1/upload/
```

### 12.2 Endpoints

| Endpoint | Methods | Description |
|---|---|---|
| `/api/auth/token/` | POST | Obtain DRF token. |
| `/api/me/` | GET | Current user profile. |
| `/api/organizations/` | GET, POST | Organizations. |
| `/api/projects/` | GET, POST | Projects. |
| `/api/projects/{id}/upload/` | POST | Upload ZIP and queue scan. |
| `/api/archives/` | GET | Uploaded archive metadata. |
| `/api/scans/` | GET, POST | Scan history. |
| `/api/scans/{id}/queue/` | POST | Re-queue a scan. |
| `/api/scans/{id}/summary/` | GET | Full scan summary. |
| `/api/dependencies/` | GET | Parsed components. |
| `/api/sboms/` | GET | CycloneDX documents. |
| `/api/vulnerabilities/` | GET | Advisory findings. |
| `/api/secret-findings/` | GET | Secret scan results. |
| `/api/recommendations/` | GET | Grounded remediation guidance. |
| `/api/licenses/` | GET | License classification. |
| `/api/reports/` | GET | Generated report metadata. |
| `/api/graph-metrics/` | GET | Graph aggregates. |
| `/api/graph-edges/` | GET | Dependency edges. |
| `/api/risk-signals/` | GET | Risk heuristics. |
| `/api/cve-records/` | GET | Normalized CVE cache. |
| `/api/intel-sources/` | GET | Source health statuses. |
| `/api/dashboard/summary/` | GET | Platform posture summary. |
| `/api/schema/` | GET | OpenAPI schema. |

All list endpoints are paginated at 25 records per page and scoped to the authenticated user's organizations.

---

## 13. Security model

| Threat | Control | Implementation |
|---|---|---|
| Malicious ZIP paths | Reject absolute paths and `..` traversal | `dependency_parser/archive.py` |
| Symlink attacks | Reject symlink entries | `dependency_parser/archive.py` |
| Encrypted archives | Reject encrypted entries | `dependency_parser/archive.py` |
| Compression bombs | 250 MB uncompressed, 200:1 ratio caps | `SCAN_*` settings |
| Oversized uploads | 100 MB ZIP, 5,000 files, 50 MB/file | `SCAN_*` settings |
| XML entity attacks | DTD/ENTITY rejection | `defusedxml` in `parsers.py` |
| Code execution | Manifests parsed as text only | `dependency_parser` |
| Cross-tenant access | Queryset + view + DRF scoping | `organizations/permissions.py`, `config/viewsets.py` |
| Header attacks | CSP, HSTS, X-Frame, nosniff, referrer, permissions policy | `config/middleware.py`, settings |
| Session theft | Secure cookie flags in production | `SESSION_COOKIE_SECURE`, `CSRF_COOKIE_SECURE` |
| API abuse | User rate throttling | `API_RATE_LIMIT` |
| Secret leakage | Optional gitleaks, no secret logging | `vulnerability_scanner/services.py` |
| Data tampering | SHA-256 on archives, SBOMs and reports | storage/model fields |
| Fake advisories | Real OSV/NVD with source attribution | `cve_intelligence/clients.py` |

---

## 14. Reports and artifacts

| Artifact | Format | Generated by | Contains |
|---|---|---|---|
| CycloneDX SBOM | `.json` | `sbom_generator/service.py` | Components, purls, licenses, dependencies, SHA-256. |
| Vulnerability report | `.pdf` | `reports/services.py` | Executive summary, findings, severity, recommendations. |
| Vulnerability CSV | `.csv` | `reports/services.py` | Flat advisory export for spreadsheets/SIEM. |
| Risk summary | `.json` | `reports/views.py` | Scores, signals, graph metrics, source status. |
| Graph export | `.json` | `reports/views.py` | Nodes, edges, metrics and vulnerable paths. |
| License report | stored model + UI | `license_compliance/service.py` | Categories, conflicts, review flags. |
| Recommendation list | stored model + UI/API | `ai_recommendations/service.py` | Prioritized actions with evidence. |

---

## 15. Testing and verification

### 15.1 What is covered

- Manifest parsers for all supported ecosystems.
- ZIP security validation: traversal, symlink, encryption, size and ratio.
- purl generation.
- Full scan pipeline with mocked OSV payloads.
- CycloneDX JSON generation and hashing.
- PDF report generation.
- HTML rendering and permission denial.
- API schema generation with DRF.
- Organization-scoped querysets.
- Upload handling and scan creation.
- Optional live OSV integration test.

### 15.2 Latest verified result

```text
Found 18 test(s).
System check identified no issues (0 silenced).
Ran 18 tests in ~14s
OK (skipped=1)
```

The skipped test is the live OSV check, enabled only with `RUN_LIVE_OSV_TEST=1`.

### 15.3 Production checks

```powershell
python manage.py check --deploy
python manage.py collectstatic --noinput
python manage.py test tests -v 1
```

---

## 16. Recommended reading order

| Order | Document | Why |
|---:|---|---|
| 1 | This `README.md` | Start here for the whole platform. |
| 2 | `docs/ARCHITECTURE.md` | Module boundaries and scan pipeline. |
| 3 | `docs/ER_DIAGRAM.md` | Database relationships and constraints. |
| 4 | `docs/API.md` | Endpoint and authentication details. |
| 5 | `docs/DEPLOYMENT.md` | Production hardening and operations. |
| 6 | `config/settings.py` | Source of truth for configuration. |
| 7 | `vulnerability_scanner/tasks.py` | Source of truth for scan execution. |
| 8 | `tests/` | Executable examples of expected behavior. |

---

## 17. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `ModuleNotFoundError: django` | Virtualenv not active or deps missing | Activate `.venv` and run `pip install -r requirements.txt`. |
| `connection to server ... failed` | PostgreSQL not running or wrong DSN | Check `DATABASE_URL` / `DB_*` and service health. |
| `No directory at: staticfiles` | Static files not collected | Run `python manage.py collectstatic --noinput`. |
| `403 Forbidden` on project page | User is not an organization member | Add membership with a valid role. |
| Scans stay `PENDING` | Worker not consuming `scans` queue | Start Celery worker or set `CELERY_TASK_ALWAYS_EAGER=True` locally. |
| `docker` not recognized | Docker CLI not installed | Install Docker Desktop and reopen terminal. |
| OSV source shows degraded | Network/API issue | Check outbound HTTPS and `SCAN_HTTP_TIMEOUT`. |
| NVD warnings | Missing/invalid key or rate limit | Set `NVD_API_KEY` or disable `ENABLE_NVD_ENRICHMENT`. |
| Source map warning on collectstatic | Vendored map missing | Keep `static/vendor/chart.umd.js.map` in place. |
| Permission denied during migration | DB user lacks rights | Grant privileges or use a superuser for initial migration. |

---

## 18. Roadmap

| Phase | Planned improvement |
|---|---|
| Phase 1 | Current platform: parsing, SBOM, OSV/NVD, graph, reports, UI, API, Docker. |
| Phase 2 | Package URL-based deduplication across scans. |
| Phase 3 | GraphQL read API and webhook notifications. |
| Phase 4 | Helm chart and Kubernetes CronJobs. |
| Phase 5 | SBOM diff viewer with drift alerts. |
| Phase 6 | Policy-as-code gates for CI/CD. |
| Phase 7 | Multi-language risk dashboards and localization. |

---

## 19. Contributing

1. Fork the repository.
2. Create a feature branch: `git checkout -b feature/your-feature`.
3. Make changes inside `supply-chain/`.
4. Run tests: `python manage.py test tests -v 2`.
5. Run checks: `python manage.py check` and `python manage.py check --deploy`.
6. Commit with a clear message.
7. Open a pull request describing the change and verification.

Please do not commit secrets, real API keys, uploaded archives, generated reports, `db.sqlite3` or `staticfiles/`.

---

## 20. Author and license

**Built and maintained by Njbalamani**

| | |
|---|---|
| Author | **Njbalamani** |
| GitHub | [Njbalamani/Supply-ChainX](https://github.com/Njbalamani/Supply-ChainX) |
| License | MIT |
| Copyright | Copyright (c) 2026 Njbalamani |

MIT License summary: you may use, copy, modify, merge, publish, distribute, sublicense and/or sell copies of the software, provided the copyright notice and permission notice are included. The software is provided "as is", without warranty of any kind.

Full text is in `LICENSE` inside this folder.
