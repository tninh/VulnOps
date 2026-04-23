"""
VulnOps Enrichment Worker
Celery workers that pull from Redis queue, call NVD and EPSS APIs,
and store enriched records in PostgreSQL.
"""

import json
import time
import logging
import os
from datetime import datetime

import requests
import psycopg2
import redis
from psycopg2.extras import RealDictCursor
from celery import Celery

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://vulnops:vulnops@postgres:5432/vulnops")

celery_app = Celery("enrichment", broker=REDIS_URL, backend=REDIS_URL)

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API_BASE = "https://api.first.org/data/v1/epss"


def get_db():
    return psycopg2.connect(DATABASE_URL)


def init_db():
    """Initialize database schema."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id UUID PRIMARY KEY,
            source VARCHAR(50),
            asset VARCHAR(255),
            cve_id VARCHAR(100),
            severity VARCHAR(20),
            cvss_score FLOAT,
            epss_score FLOAT,
            epss_percentile FLOAT,
            description TEXT,
            package VARCHAR(255),
            installed_version VARCHAR(100),
            fixed_version VARCHAR(100),
            ai_risk_tier VARCHAR(20),
            ai_rationale TEXT,
            ai_remediation TEXT,
            sla_deadline TIMESTAMP,
            status VARCHAR(50) DEFAULT 'open',
            jira_ticket VARCHAR(100),
            ingested_at TIMESTAMP,
            enriched_at TIMESTAMP,
            remediated_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT NOW(),
            updated_at TIMESTAMP DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id SERIAL PRIMARY KEY,
            vuln_id UUID,
            action VARCHAR(100),
            old_status VARCHAR(50),
            new_status VARCHAR(50),
            actor VARCHAR(100),
            notes TEXT,
            created_at TIMESTAMP DEFAULT NOW()
        );

        CREATE INDEX IF NOT EXISTS idx_vulns_cve_id ON vulnerabilities(cve_id);
        CREATE INDEX IF NOT EXISTS idx_vulns_status ON vulnerabilities(status);
        CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity);
        CREATE INDEX IF NOT EXISTS idx_vulns_sla_deadline ON vulnerabilities(sla_deadline);
    """)
    conn.commit()
    cur.close()
    conn.close()
    logger.info("Database initialized")


def fetch_nvd_data(cve_id: str) -> dict:
    """Fetch CVE details from NVD API v2."""
    try:
        resp = requests.get(
            NVD_API_BASE,
            params={"cveId": cve_id},
            timeout=10,
            headers={"User-Agent": "VulnOps/1.0"}
        )
        if resp.status_code == 200:
            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            if vulns:
                cve = vulns[0].get("cve", {})
                metrics = cve.get("metrics", {})
                cvss_v3 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
                desc = cve.get("descriptions", [{}])
                english_desc = next(
                    (d["value"] for d in desc if d.get("lang") == "en"), ""
                )
                return {
                    "cvss_score": cvss_v3.get("baseScore"),
                    "cvss_vector": cvss_v3.get("vectorString", ""),
                    "description": english_desc[:1000],
                }
        time.sleep(0.6)  # NVD rate limit
    except Exception as e:
        logger.warning(f"NVD fetch failed for {cve_id}: {e}")
    return {}


def fetch_epss_score(cve_id: str) -> dict:
    """Fetch EPSS exploit probability score from FIRST."""
    try:
        resp = requests.get(
            EPSS_API_BASE,
            params={"cve": cve_id},
            timeout=10
        )
        if resp.status_code == 200:
            data = resp.json().get("data", [])
            if data:
                return {
                    "epss_score": float(data[0].get("epss", 0)),
                    "epss_percentile": float(data[0].get("percentile", 0)),
                }
    except Exception as e:
        logger.warning(f"EPSS fetch failed for {cve_id}: {e}")
    return {}


def compute_sla_deadline(severity: str, ingested_at: str) -> datetime:
    """Compute SLA deadline based on severity tier."""
    from datetime import timedelta
    base = datetime.fromisoformat(ingested_at)
    sla_days = {"CRITICAL": 1, "HIGH": 7, "MEDIUM": 30, "LOW": 90, "UNKNOWN": 90}
    days = sla_days.get(severity, 90)
    return base + timedelta(days=days)


def upsert_vulnerability(record: dict):
    """Upsert enriched vulnerability into PostgreSQL."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO vulnerabilities (
            id, source, asset, cve_id, severity, cvss_score, epss_score,
            epss_percentile, description, package, installed_version,
            fixed_version, sla_deadline, status, ingested_at, enriched_at
        ) VALUES (
            %(id)s, %(source)s, %(asset)s, %(cve_id)s, %(severity)s,
            %(cvss_score)s, %(epss_score)s, %(epss_percentile)s,
            %(description)s, %(package)s, %(installed_version)s,
            %(fixed_version)s, %(sla_deadline)s, 'enriched',
            %(ingested_at)s, NOW()
        )
        ON CONFLICT (id) DO UPDATE SET
            cvss_score = EXCLUDED.cvss_score,
            epss_score = EXCLUDED.epss_score,
            epss_percentile = EXCLUDED.epss_percentile,
            description = EXCLUDED.description,
            sla_deadline = EXCLUDED.sla_deadline,
            status = 'enriched',
            enriched_at = NOW(),
            updated_at = NOW()
    """, record)
    conn.commit()
    cur.close()
    conn.close()


@celery_app.task(name="enrich_vulnerability", bind=True, max_retries=3)
def enrich_vulnerability(self, record_json: str):
    """Main enrichment task: fetch NVD + EPSS data and store."""
    record = json.loads(record_json)
    cve_id = record.get("cve_id", "")

    if not cve_id or not cve_id.startswith("CVE-"):
        logger.info(f"Skipping non-CVE record: {cve_id}")
        return

    logger.info(f"Enriching {cve_id}")

    nvd_data = fetch_nvd_data(cve_id)
    epss_data = fetch_epss_score(cve_id)

    if nvd_data.get("cvss_score"):
        record["cvss_score"] = nvd_data["cvss_score"]
    if nvd_data.get("description"):
        record["description"] = nvd_data["description"]

    record["epss_score"] = epss_data.get("epss_score", 0.0)
    record["epss_percentile"] = epss_data.get("epss_percentile", 0.0)
    record["sla_deadline"] = compute_sla_deadline(
        record.get("severity", "UNKNOWN"),
        record.get("ingested_at", datetime.utcnow().isoformat())
    ).isoformat()

    try:
        upsert_vulnerability(record)
        logger.info(f"Stored {cve_id} — CVSS:{record.get('cvss_score')} EPSS:{record.get('epss_score'):.4f}")
    except Exception as e:
        logger.error(f"DB error for {cve_id}: {e}")
        raise self.retry(exc=e, countdown=30)


def process_queue_loop():
    """Standalone loop that drains Redis queue and dispatches Celery tasks."""
    r = redis.Redis.from_url(REDIS_URL, decode_responses=True)
    logger.info("Enrichment queue processor started")

    while True:
        item = r.blpop("enrichment_queue", timeout=5)
        if item:
            _, record_json = item
            enrich_vulnerability.delay(record_json)
        time.sleep(0.1)


if __name__ == "__main__":
    init_db()
    process_queue_loop()
