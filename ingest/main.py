"""
VulnOps Ingest Service
Accepts Trivy JSON and OpenSCAP XML scan outputs,
normalizes them into a unified schema, and queues for enrichment.
"""

import json
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Any

import redis
from fastapi import FastAPI, HTTPException, UploadFile, File, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from prometheus_client import Counter, Gauge, generate_latest, CONTENT_TYPE_LATEST
from fastapi.responses import Response
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="VulnOps Ingest API",
    description="Vulnerability scan ingestion and normalization service",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Prometheus metrics
VULNS_INGESTED = Counter("vulnops_vulns_ingested_total", "Total vulnerabilities ingested", ["source", "severity"])
SCANS_PROCESSED = Counter("vulnops_scans_processed_total", "Total scans processed", ["source"])
QUEUE_SIZE = Gauge("vulnops_queue_size", "Current enrichment queue size")

# Redis connection
try:
    r = redis.Redis(host="redis", port=6379, decode_responses=True)
    r.ping()
    logger.info("Redis connected")
except Exception:
    logger.warning("Redis not available — running in demo mode")
    r = None


class VulnerabilityRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source: str
    asset: str
    cve_id: str
    severity: str
    cvss_score: float | None = None
    description: str = ""
    package: str = ""
    installed_version: str = ""
    fixed_version: str = ""
    ingested_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    status: str = "new"


def normalize_severity(raw: str) -> str:
    mapping = {
        "critical": "CRITICAL",
        "high": "HIGH",
        "medium": "MEDIUM",
        "moderate": "MEDIUM",
        "low": "LOW",
        "negligible": "LOW",
        "unknown": "UNKNOWN",
    }
    return mapping.get(raw.lower(), "UNKNOWN")


def parse_trivy_json(data: dict) -> list[VulnerabilityRecord]:
    """Parse Trivy JSON output into normalized VulnerabilityRecord list."""
    records = []
    asset = data.get("ArtifactName", "unknown")
    results = data.get("Results", [])

    for result in results:
        vulns = result.get("Vulnerabilities") or []
        for v in vulns:
            record = VulnerabilityRecord(
                source="trivy",
                asset=asset,
                cve_id=v.get("VulnerabilityID", ""),
                severity=normalize_severity(v.get("Severity", "unknown")),
                cvss_score=v.get("CVSS", {}).get("nvd", {}).get("V3Score"),
                description=v.get("Description", "")[:500],
                package=v.get("PkgName", ""),
                installed_version=v.get("InstalledVersion", ""),
                fixed_version=v.get("FixedVersion", ""),
            )
            records.append(record)
    return records


def parse_openscap_xml(xml_content: str) -> list[VulnerabilityRecord]:
    """Parse OpenSCAP XML report into normalized VulnerabilityRecord list."""
    records = []
    try:
        root = ET.fromstring(xml_content)
        ns = {"oval": "http://oval.mitre.org/XMLSchema/oval-results-5"}
        asset = root.findtext(".//system", default="linux-host")

        for result in root.iter("rule-result"):
            rule_id = result.get("idref", "")
            check_result = result.findtext("result", "")
            if check_result == "fail":
                severity_map = {"high": "HIGH", "medium": "MEDIUM", "low": "LOW"}
                severity = severity_map.get(result.get("severity", "").lower(), "MEDIUM")
                record = VulnerabilityRecord(
                    source="openscap",
                    asset=asset,
                    cve_id=rule_id,
                    severity=severity,
                    description=result.findtext("message", "")[:500],
                )
                records.append(record)
    except ET.ParseError as e:
        logger.error(f"XML parse error: {e}")
    return records


def queue_for_enrichment(records: list[VulnerabilityRecord]):
    """Push normalized records to Redis enrichment queue."""
    if r is None:
        logger.warning(f"No Redis — would queue {len(records)} records")
        return
    pipe = r.pipeline()
    for rec in records:
        pipe.rpush("enrichment_queue", rec.model_dump_json())
    pipe.execute()
    QUEUE_SIZE.set(r.llen("enrichment_queue"))


@app.get("/health")
def health():
    return {"status": "ok", "service": "ingest", "timestamp": datetime.utcnow().isoformat()}


@app.post("/ingest/trivy", response_model=dict)
async def ingest_trivy(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    """Accept a Trivy JSON scan file and ingest it."""
    content = await file.read()
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    records = parse_trivy_json(data)
    if not records:
        return {"message": "No vulnerabilities found", "count": 0}

    background_tasks.add_task(queue_for_enrichment, records)

    for rec in records:
        VULNS_INGESTED.labels(source="trivy", severity=rec.severity).inc()
    SCANS_PROCESSED.labels(source="trivy").inc()

    logger.info(f"Trivy: ingested {len(records)} vulns from {data.get('ArtifactName','unknown')}")
    return {"message": "Ingested", "count": len(records), "scan_id": str(uuid.uuid4())}


@app.post("/ingest/openscap", response_model=dict)
async def ingest_openscap(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    """Accept an OpenSCAP XML report and ingest it."""
    content = await file.read()
    records = parse_openscap_xml(content.decode("utf-8"))

    background_tasks.add_task(queue_for_enrichment, records)

    for rec in records:
        VULNS_INGESTED.labels(source="openscap", severity=rec.severity).inc()
    SCANS_PROCESSED.labels(source="openscap").inc()

    logger.info(f"OpenSCAP: ingested {len(records)} findings")
    return {"message": "Ingested", "count": len(records)}


@app.post("/ingest/json", response_model=dict)
async def ingest_custom_json(payload: list[dict], background_tasks: BackgroundTasks):
    """Accept a custom JSON array of vulnerability records."""
    records = []
    for item in payload:
        try:
            rec = VulnerabilityRecord(
                source=item.get("source", "custom"),
                asset=item.get("asset", "unknown"),
                cve_id=item.get("cve_id", ""),
                severity=normalize_severity(item.get("severity", "unknown")),
                cvss_score=item.get("cvss_score"),
                description=item.get("description", ""),
                package=item.get("package", ""),
                installed_version=item.get("installed_version", ""),
                fixed_version=item.get("fixed_version", ""),
            )
            records.append(rec)
        except Exception as e:
            logger.warning(f"Skipping malformed record: {e}")

    background_tasks.add_task(queue_for_enrichment, records)
    SCANS_PROCESSED.labels(source="custom").inc()

    return {"message": "Ingested", "count": len(records)}


@app.get("/metrics")
def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
