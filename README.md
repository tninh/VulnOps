# VulnOps — Vulnerability Operations Platform

**An end-to-end vulnerability management pipeline with AI-powered risk scoring, automated remediation, and SLA tracking. Built for regulated cloud environments.**

---

## Architecture

```
Trivy / OpenSCAP → FastAPI Ingest → Redis Queue → Celery Workers (Enrichment)
                                                         ↓
                                         NVD API + EPSS API (external)
                                                         ↓
                                            PostgreSQL (enriched records)
                                                         ↓
                                          AI Prioritizer (LLM scoring)
                                                         ↓
                                     Jira Tickets + Ansible Auto-Patch
                                                         ↓
                              Prometheus Metrics → Grafana Dashboard
```

---

## Services

| Service | Port | Purpose |
|---|---|---|
| `ingest` | 8001 | FastAPI — accepts Trivy JSON and OpenSCAP XML |
| `enrichment` | — | Celery workers — NVD + EPSS enrichment |
| `prioritizer` | 8002 | FastAPI + AI scoring engine |
| `remediation` | 8003 | FastAPI — Jira integration + Ansible triggers |
| `dashboard` | 3000 | Security operations dashboard |
| `grafana` | 3001 | Metrics dashboards |
| `prometheus` | 9090 | Metrics collection |
| `postgres` | 5432 | Primary data store |
| `redis` | 6379 | Enrichment queue + Celery broker |

---

## Quick Start

### Prerequisites
- Docker + Docker Compose
- (Optional) OpenAI API key for AI scoring

### 1. Clone and configure
```bash
git clone https://github.com/yourname/vulnops.git
cd vulnops
cp .env.example .env
# Edit .env to add OPENAI_API_KEY, JIRA_URL, SLACK_WEBHOOK_URL
```

### 2. Start the stack
```bash
docker compose up --build
```

### 3. Verify services
```bash
curl http://localhost:8001/health   # ingest
curl http://localhost:8002/health   # prioritizer
curl http://localhost:8003/health   # remediation
```

### 4. Open the dashboard
Navigate to `http://localhost:3000`

---

## Ingesting Scan Results

### Trivy (container scanning)
```bash
# Run a real Trivy scan
trivy image --format json --output nginx-scan.json nginx:1.23

# Ingest the results
curl -X POST http://localhost:8001/ingest/trivy \
  -F "file=@nginx-scan.json"

# Response
# {"message":"Ingested","count":12,"scan_id":"..."}
```

### OpenSCAP (OS compliance)
```bash
# Run an OpenSCAP scan (on the target host)
oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_cis \
  --results scan-results.xml /usr/share/xml/scap/ssg/content/ssg-rhel8-ds.xml

# Ingest results
curl -X POST http://localhost:8001/ingest/openscap \
  -F "file=@scan-results.xml"
```

### Custom JSON
```bash
curl -X POST http://localhost:8001/ingest/json \
  -H "Content-Type: application/json" \
  -d '[{
    "source": "custom",
    "asset": "web-prod-01",
    "cve_id": "CVE-2023-44487",
    "severity": "critical",
    "package": "nghttp2",
    "installed_version": "1.43.0-1",
    "fixed_version": "1.43.0-1+deb11u1"
  }]'
```

---

## AI Risk Scoring

The prioritizer uses an LLM to assess contextual risk beyond raw CVSS scores.

**Prompt design:**
- Feeds CVSS score, CVSS vector string, EPSS score, EPSS percentile, asset context, and description
- Requests structured JSON: `risk_tier`, `risk_score`, `rationale`, `remediation_steps`, `compensating_controls`, `estimated_effort`
- Temperature set to 0.2 for reproducible, conservative scoring

**SLA assignment (automatic):**
| Severity | SLA |
|---|---|
| CRITICAL | 24 hours |
| HIGH | 7 days |
| MEDIUM | 30 days |
| LOW | 90 days |

**Trigger manual prioritization batch:**
```bash
curl -X POST http://localhost:8002/prioritize/run?limit=50
```

**Without OpenAI API key:**
Falls back to a deterministic heuristic scorer (CVSS + EPSS weighted rules). Results will clearly indicate heuristic mode.

---

## Querying Vulnerabilities

```bash
# All open critical vulnerabilities
curl "http://localhost:8002/vulnerabilities?severity=CRITICAL&status=prioritized"

# Aggregate stats
curl http://localhost:8002/stats

# Update status + audit trail
curl -X PATCH "http://localhost:8002/vulnerabilities/{id}/status?status=remediated&notes=Patched+by+team&actor=jane.smith"
```

---

## Remediation Workflow

### Automatic (Jira + Ansible)
1. Enriched vulns → AI Prioritizer assigns `ai_risk_tier`
2. Remediation service creates Jira ticket with SLA deadline and AI remediation steps
3. CRITICAL vulns with available `fixed_version` → Ansible `patch_package.yml` triggered
4. All state changes logged to `audit_log` table

### Manual Ansible trigger
```bash
ansible-playbook remediation/patch_package.yml \
  --extra-vars "target_host=web-prod-01 package_name=openssl target_version=3.0.8 cve_id=CVE-2023-0286" \
  -i inventory/production.yml
```

---

## AWS Deployment

```bash
cd infra/terraform

# Initialize
terraform init

# Review plan
terraform plan \
  -var="db_password=<strong_random_password>" \
  -var="openai_api_key=<your_key>"

# Deploy
terraform apply \
  -var="db_password=<strong_random_password>" \
  -var="openai_api_key=<your_key>"
```

**What gets deployed:**
- ECS Fargate cluster (ingest, prioritizer, remediation services)
- RDS PostgreSQL 15 (Multi-AZ, encrypted at rest)
- ElastiCache Redis (cluster mode, TLS)
- VPC with public/private subnet separation
- All services in private subnets; only ALB in public subnet

---

## Running Tests

```bash
# Install test dependencies
pip install pytest requests psycopg2-binary celery fastapi pydantic

# Run full suite
pytest tests/ -v

# Run specific test class
pytest tests/test_vulnops.py::TestSLADeadlines -v

# Coverage report
pytest tests/ --cov=. --cov-report=term-missing
```

---

## Observability

**Prometheus metrics exposed:**

| Metric | Description |
|---|---|
| `vulnops_vulns_ingested_total` | Total vulns ingested, labeled by source and severity |
| `vulnops_scans_processed_total` | Scans processed by source |
| `vulnops_queue_size` | Current enrichment queue depth |
| `vulnops_ai_scores_total` | AI scoring calls completed |
| `vulnops_ai_latency_seconds` | AI scoring latency histogram |

**Grafana dashboards (auto-provisioned at port 3001):**
- SLA breach rate over time
- Severity distribution trends
- Mean time to remediate (MTTR) by severity
- Enrichment queue depth

**Alerting (configure in `observability/alerts.yml`):**
- `CriticalSLABreached` — fires when a CRITICAL vuln exceeds its 24h SLA
- `QueueDepthHigh` — fires when enrichment queue exceeds 500 items
- `RemediationStalled` — fires when no vulns remediated in 48h

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `DATABASE_URL` | Yes | PostgreSQL connection string |
| `REDIS_URL` | Yes | Redis connection string |
| `OPENAI_API_KEY` | No | Enables LLM scoring (falls back to heuristic) |
| `OPENAI_BASE_URL` | No | Override for Ollama or Azure OpenAI |
| `AI_MODEL` | No | LLM model (default: gpt-4o-mini) |
| `JIRA_URL` | No | Jira instance URL |
| `JIRA_USER` | No | Jira service account email |
| `JIRA_TOKEN` | No | Jira API token |
| `JIRA_PROJECT` | No | Jira project key (default: VULN) |
| `SLACK_WEBHOOK_URL` | No | Slack incoming webhook for alerts |

---

## Project Structure

```
vulnops/
├── ingest/
│   ├── main.py              # FastAPI ingest service (Trivy, OpenSCAP, JSON)
│   └── Dockerfile
├── enrichment/
│   ├── worker.py            # Celery workers + NVD/EPSS API calls
│   └── Dockerfile
├── prioritizer/
│   ├── main.py              # AI scoring engine + vulnerability query API
│   └── Dockerfile
├── remediation/
│   ├── main.py              # Jira integration + Ansible trigger
│   ├── patch_package.yml    # Ansible playbook
│   └── Dockerfile
├── dashboard/
│   └── index.html           # Security operations dashboard
├── observability/
│   ├── prometheus.yml       # Scrape configuration
│   └── grafana/             # Dashboard + datasource provisioning
├── infra/
│   └── terraform/
│       └── main.tf          # AWS ECS + RDS + ElastiCache
├── tests/
│   └── test_vulnops.py      # pytest suite (50+ tests)
├── docker-compose.yml       # Full local stack
└── README.md
```

---

## Compliance Notes

This platform is designed for regulated environments:

- **Audit trail:** Every status change written to `audit_log` with actor, timestamp, and notes
- **Encryption:** RDS and ElastiCache encrypted at rest and in transit (TLS)
- **Network isolation:** All services in private VPC subnets; no direct public exposure
- **Principle of least privilege:** IAM roles scoped per ECS task
- **SLA enforcement:** Prometheus alerting fires before SLA breach, not after

---

*Built as a portfolio project demonstrating vulnerability management, Linux systems engineering, containerized services, AI integration, and cloud infrastructure skills.*
