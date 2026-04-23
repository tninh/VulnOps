"""
VulnOps AI Prioritizer
Uses an LLM to assess contextual risk, assign remediation priority,
and generate human-readable remediation guidance.
Also exposes a FastAPI interface for the dashboard to query prioritized vulns.
"""

import os
import json
import logging
from datetime import datetime, timezone
from typing import Optional

import psycopg2
import psycopg2.extras
import requests
from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
from fastapi.responses import Response

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://vulnops:vulnops@postgres:5432/vulnops")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
AI_MODEL = os.getenv("AI_MODEL", "gpt-4o-mini")

app = FastAPI(title="VulnOps Prioritizer API", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

AI_SCORES_COMPUTED = Counter("vulnops_ai_scores_total", "Total AI risk scores computed")
AI_LATENCY = Histogram("vulnops_ai_latency_seconds", "AI scoring latency")

RISK_TIERS = {
    "CRITICAL": {"label": "Patch Immediately", "color": "#E24B4A"},
    "HIGH": {"label": "Patch This Week", "color": "#EF9F27"},
    "MEDIUM": {"label": "Patch This Month", "color": "#378ADD"},
    "LOW": {"label": "Monitor", "color": "#5DCAA5"},
}


def get_db():
    return psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)


AI_SCORING_PROMPT = """You are a senior vulnerability management engineer at a company running regulated cloud infrastructure (FedRAMP-adjacent). Your job is to assess the risk of a given CVE in context and provide actionable remediation guidance.

Given vulnerability data, respond ONLY with a valid JSON object (no markdown, no preamble):

{{
  "risk_tier": "<CRITICAL|HIGH|MEDIUM|LOW>",
  "risk_score": <integer 0-100>,
  "rationale": "<2-3 sentence explanation of the risk considering CVSS, exploitability, and asset context>",
  "remediation_steps": [
    "<Step 1>",
    "<Step 2>",
    "<Step 3>"
  ],
  "compensating_controls": "<What to do if an immediate patch is not possible>",
  "estimated_effort": "<minutes|hours|days>"
}}

Vulnerability data:
- CVE ID: {cve_id}
- Severity: {severity}
- CVSS Score: {cvss_score}
- CVSS Vector: {cvss_vector}
- EPSS Score: {epss_score} (probability this is exploited in the next 30 days)
- EPSS Percentile: {epss_percentile}
- Affected Package: {package} {installed_version}
- Fixed Version Available: {fixed_version}
- Asset: {asset}
- Description: {description}

Consider: high EPSS scores (>0.5) mean active exploitation is likely. CVSS alone is insufficient — weight EPSS heavily.
"""


def call_llm(prompt: str) -> dict:
    """Call LLM API for AI risk scoring. Falls back to heuristic if no key."""
    if not OPENAI_API_KEY:
        return _heuristic_score_fallback(prompt)

    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": AI_MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.2,
        "max_tokens": 600,
        "response_format": {"type": "json_object"},
    }

    with AI_LATENCY.time():
        resp = requests.post(
            f"{OPENAI_BASE_URL}/chat/completions",
            headers=headers,
            json=payload,
            timeout=30,
        )
        resp.raise_for_status()
        content = resp.json()["choices"][0]["message"]["content"]
        return json.loads(content)


def _heuristic_score_fallback(prompt: str) -> dict:
    """Rule-based scoring when no LLM key is configured."""
    cvss = 0.0
    epss = 0.0
    severity = "MEDIUM"

    for line in prompt.split("\n"):
        if "CVSS Score:" in line:
            try:
                cvss = float(line.split(":")[-1].strip())
            except ValueError:
                pass
        if "EPSS Score:" in line:
            try:
                epss = float(line.split(":")[-1].split("(")[0].strip())
            except ValueError:
                pass
        if "Severity:" in line:
            severity = line.split(":")[-1].strip()

    if cvss >= 9.0 or epss > 0.7:
        tier = "CRITICAL"
        score = 95
    elif cvss >= 7.0 or epss > 0.3:
        tier = "HIGH"
        score = 70
    elif cvss >= 4.0:
        tier = "MEDIUM"
        score = 45
    else:
        tier = "LOW"
        score = 20

    return {
        "risk_tier": tier,
        "risk_score": score,
        "rationale": f"Heuristic score based on CVSS {cvss} and EPSS {epss:.3f}. Configure OPENAI_API_KEY for AI-powered analysis.",
        "remediation_steps": [
            "Review the CVE advisory and confirm applicability",
            "Apply available package update if fixed_version is listed",
            "Verify fix by re-running vulnerability scanner",
        ],
        "compensating_controls": "Restrict network access to affected service; enable enhanced logging.",
        "estimated_effort": "hours",
    }


def score_vulnerability(vuln: dict) -> dict:
    """Run AI scoring on a single vulnerability record."""
    prompt = AI_SCORING_PROMPT.format(
        cve_id=vuln.get("cve_id", ""),
        severity=vuln.get("severity", ""),
        cvss_score=vuln.get("cvss_score") or "N/A",
        cvss_vector=vuln.get("cvss_vector") or "N/A",
        epss_score=vuln.get("epss_score") or 0.0,
        epss_percentile=vuln.get("epss_percentile") or 0.0,
        package=vuln.get("package") or "",
        installed_version=vuln.get("installed_version") or "",
        fixed_version=vuln.get("fixed_version") or "Not yet available",
        asset=vuln.get("asset") or "unknown",
        description=(vuln.get("description") or "")[:400],
    )

    result = call_llm(prompt)
    AI_SCORES_COMPUTED.inc()
    return result


def run_prioritization_batch(limit: int = 50):
    """Score enriched vulns that haven't been AI-scored yet."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT * FROM vulnerabilities
        WHERE status = 'enriched' AND ai_risk_tier IS NULL
        ORDER BY cvss_score DESC NULLS LAST, epss_score DESC NULLS LAST
        LIMIT %s
    """, (limit,))
    rows = cur.fetchall()

    for row in rows:
        vuln = dict(row)
        try:
            ai_result = score_vulnerability(vuln)
            cur.execute("""
                UPDATE vulnerabilities SET
                    ai_risk_tier = %s,
                    ai_rationale = %s,
                    ai_remediation = %s,
                    status = 'prioritized',
                    updated_at = NOW()
                WHERE id = %s
            """, (
                ai_result.get("risk_tier"),
                ai_result.get("rationale", ""),
                json.dumps({
                    "steps": ai_result.get("remediation_steps", []),
                    "compensating_controls": ai_result.get("compensating_controls", ""),
                    "estimated_effort": ai_result.get("estimated_effort", "unknown"),
                    "risk_score": ai_result.get("risk_score", 0),
                }),
                vuln["id"],
            ))
            conn.commit()
            logger.info(f"Scored {vuln['cve_id']}: {ai_result.get('risk_tier')} (score={ai_result.get('risk_score')})")
        except Exception as e:
            logger.error(f"Scoring failed for {vuln.get('cve_id')}: {e}")
            conn.rollback()

    cur.close()
    conn.close()
    return len(rows)


# --- FastAPI endpoints for dashboard ---

@app.get("/health")
def health():
    return {"status": "ok", "service": "prioritizer"}


@app.get("/vulnerabilities")
def list_vulnerabilities(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    risk_tier: Optional[str] = None,
    limit: int = Query(default=100, le=500),
    offset: int = 0,
):
    conn = get_db()
    cur = conn.cursor()
    filters = []
    params = []

    if status:
        filters.append("status = %s")
        params.append(status)
    if severity:
        filters.append("severity = %s")
        params.append(severity)
    if risk_tier:
        filters.append("ai_risk_tier = %s")
        params.append(risk_tier)

    where = "WHERE " + " AND ".join(filters) if filters else ""
    cur.execute(f"""
        SELECT * FROM vulnerabilities
        {where}
        ORDER BY
            CASE ai_risk_tier
                WHEN 'CRITICAL' THEN 1
                WHEN 'HIGH' THEN 2
                WHEN 'MEDIUM' THEN 3
                WHEN 'LOW' THEN 4
                ELSE 5
            END,
            cvss_score DESC NULLS LAST,
            epss_score DESC NULLS LAST
        LIMIT %s OFFSET %s
    """, params + [limit, offset])
    rows = [dict(r) for r in cur.fetchall()]
    cur.close()
    conn.close()
    return rows


@app.get("/stats")
def get_stats():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT
            COUNT(*) as total,
            COUNT(*) FILTER (WHERE severity = 'CRITICAL') as critical,
            COUNT(*) FILTER (WHERE severity = 'HIGH') as high,
            COUNT(*) FILTER (WHERE severity = 'MEDIUM') as medium,
            COUNT(*) FILTER (WHERE severity = 'LOW') as low,
            COUNT(*) FILTER (WHERE status = 'open' OR status = 'enriched' OR status = 'prioritized') as open_count,
            COUNT(*) FILTER (WHERE status = 'remediated') as remediated_count,
            COUNT(*) FILTER (WHERE sla_deadline < NOW() AND status != 'remediated') as sla_breached,
            COUNT(*) FILTER (WHERE sla_deadline BETWEEN NOW() AND NOW() + INTERVAL '48 hours' AND status != 'remediated') as sla_warning,
            ROUND(AVG(cvss_score)::numeric, 2) as avg_cvss,
            ROUND(AVG(epss_score)::numeric, 4) as avg_epss
        FROM vulnerabilities
    """)
    stats = dict(cur.fetchone())

    cur.execute("""
        SELECT asset, COUNT(*) as count
        FROM vulnerabilities
        WHERE status != 'remediated'
        GROUP BY asset
        ORDER BY count DESC
        LIMIT 10
    """)
    stats["top_assets"] = [dict(r) for r in cur.fetchall()]

    cur.execute("""
        SELECT source, COUNT(*) as count
        FROM vulnerabilities
        GROUP BY source
    """)
    stats["by_source"] = [dict(r) for r in cur.fetchall()]

    cur.close()
    conn.close()
    return stats


@app.post("/prioritize/run")
def trigger_prioritization(limit: int = 50):
    """Manually trigger a prioritization batch."""
    count = run_prioritization_batch(limit)
    return {"message": f"Scored {count} vulnerabilities"}


@app.patch("/vulnerabilities/{vuln_id}/status")
def update_status(vuln_id: str, status: str, notes: str = "", actor: str = "system"):
    """Update vulnerability status and log to audit trail."""
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT status FROM vulnerabilities WHERE id = %s", (vuln_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return {"error": "Not found"}

    old_status = row["status"]
    update_fields = {"status": status, "updated_at": "NOW()"}
    if status == "remediated":
        update_fields["remediated_at"] = "NOW()"

    cur.execute("""
        UPDATE vulnerabilities SET status = %s, updated_at = NOW()
        WHERE id = %s
    """, (status, vuln_id))

    cur.execute("""
        INSERT INTO audit_log (vuln_id, action, old_status, new_status, actor, notes)
        VALUES (%s, 'status_change', %s, %s, %s, %s)
    """, (vuln_id, old_status, status, actor, notes))

    conn.commit()
    cur.close()
    conn.close()
    return {"message": "Updated", "old_status": old_status, "new_status": status}


@app.get("/metrics")
def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


if __name__ == "__main__":
    import time
    logger.info("Running prioritization batch loop")
    while True:
        count = run_prioritization_batch(50)
        if count == 0:
            time.sleep(30)
        else:
            time.sleep(5)
