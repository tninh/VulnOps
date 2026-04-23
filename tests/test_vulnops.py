"""
VulnOps Test Suite
Covers: ingest parsing, severity normalization, SLA calculation,
AI prompt structure, enrichment logic, and API endpoints.
"""

import json
import pytest
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

# ─── Import modules under test ────────────────────────────────────────────────

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'ingest'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'enrichment'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'prioritizer'))

from main import (
    normalize_severity,
    parse_trivy_json,
    parse_openscap_xml,
    VulnerabilityRecord,
)
from worker import compute_sla_deadline, fetch_nvd_data, fetch_epss_score
from main import AI_SCORING_PROMPT, _heuristic_score_fallback, score_vulnerability


# ─── Fixtures ─────────────────────────────────────────────────────────────────

TRIVY_SAMPLE = {
    "ArtifactName": "nginx:1.23",
    "Results": [{
        "Target": "nginx:1.23 (debian 11.6)",
        "Vulnerabilities": [
            {
                "VulnerabilityID": "CVE-2023-44487",
                "PkgName": "nghttp2",
                "InstalledVersion": "1.43.0-1",
                "FixedVersion": "1.43.0-1+deb11u1",
                "Severity": "HIGH",
                "Description": "HTTP/2 Rapid Reset Attack vulnerability",
                "CVSS": {"nvd": {"V3Score": 7.5}},
            },
            {
                "VulnerabilityID": "CVE-2023-38408",
                "PkgName": "openssh-client",
                "InstalledVersion": "1:8.4p1-5",
                "FixedVersion": "1:8.4p1-5+deb11u2",
                "Severity": "CRITICAL",
                "Description": "Remote code execution in ssh-agent",
                "CVSS": {"nvd": {"V3Score": 9.8}},
            },
        ],
    }]
}

OPENSCAP_SAMPLE = """<?xml version="1.0" encoding="UTF-8"?>
<oval_results>
  <system>prod-web-01</system>
  <results>
    <rule-result idref="xccdf_org.ssgproject_rule_sshd_disable_root_login" severity="high">
      <result>fail</result>
      <message>SSH root login is enabled</message>
    </rule-result>
    <rule-result idref="xccdf_org.ssgproject_rule_accounts_password_minlen_login_defs" severity="medium">
      <result>fail</result>
      <message>Minimum password length not configured</message>
    </rule-result>
    <rule-result idref="xccdf_org.ssgproject_rule_auditd_enabled" severity="high">
      <result>pass</result>
      <message>Auditd is enabled</message>
    </rule-result>
  </results>
</oval_results>"""


# ─── Ingest tests ─────────────────────────────────────────────────────────────

class TestNormalizeSeverity:
    def test_critical(self):
        assert normalize_severity("critical") == "CRITICAL"
        assert normalize_severity("CRITICAL") == "CRITICAL"

    def test_high(self):
        assert normalize_severity("high") == "HIGH"

    def test_moderate_maps_to_medium(self):
        assert normalize_severity("moderate") == "MEDIUM"

    def test_negligible_maps_to_low(self):
        assert normalize_severity("negligible") == "LOW"

    def test_unknown_fallback(self):
        assert normalize_severity("xyz") == "UNKNOWN"

    def test_empty_fallback(self):
        assert normalize_severity("") == "UNKNOWN"


class TestTrivyParsing:
    def test_parses_correct_count(self):
        records = parse_trivy_json(TRIVY_SAMPLE)
        assert len(records) == 2

    def test_asset_name_extracted(self):
        records = parse_trivy_json(TRIVY_SAMPLE)
        assert all(r.asset == "nginx:1.23" for r in records)

    def test_source_is_trivy(self):
        records = parse_trivy_json(TRIVY_SAMPLE)
        assert all(r.source == "trivy" for r in records)

    def test_cvss_score_extracted(self):
        records = parse_trivy_json(TRIVY_SAMPLE)
        scores = {r.cve_id: r.cvss_score for r in records}
        assert scores["CVE-2023-44487"] == 7.5
        assert scores["CVE-2023-38408"] == 9.8

    def test_severity_normalized(self):
        records = parse_trivy_json(TRIVY_SAMPLE)
        severities = {r.cve_id: r.severity for r in records}
        assert severities["CVE-2023-44487"] == "HIGH"
        assert severities["CVE-2023-38408"] == "CRITICAL"

    def test_fixed_version_captured(self):
        records = parse_trivy_json(TRIVY_SAMPLE)
        r = next(r for r in records if r.cve_id == "CVE-2023-44487")
        assert r.fixed_version == "1.43.0-1+deb11u1"

    def test_empty_results(self):
        records = parse_trivy_json({"ArtifactName": "empty", "Results": []})
        assert records == []

    def test_no_vulns_in_result(self):
        data = {"ArtifactName": "clean", "Results": [{"Target": "clean", "Vulnerabilities": None}]}
        records = parse_trivy_json(data)
        assert records == []


class TestOpenSCAPParsing:
    def test_only_failed_rules_ingested(self):
        records = parse_openscap_xml(OPENSCAP_SAMPLE)
        # Only 2 fail, 1 pass — should get 2 records
        assert len(records) == 2

    def test_source_is_openscap(self):
        records = parse_openscap_xml(OPENSCAP_SAMPLE)
        assert all(r.source == "openscap" for r in records)

    def test_asset_from_system_element(self):
        records = parse_openscap_xml(OPENSCAP_SAMPLE)
        assert all(r.asset == "prod-web-01" for r in records)

    def test_invalid_xml_returns_empty(self):
        records = parse_openscap_xml("not valid xml <<>>")
        assert records == []

    def test_severity_mapping(self):
        records = parse_openscap_xml(OPENSCAP_SAMPLE)
        severities = {r.cve_id: r.severity for r in records}
        assert severities["xccdf_org.ssgproject_rule_sshd_disable_root_login"] == "HIGH"
        assert severities["xccdf_org.ssgproject_rule_accounts_password_minlen_login_defs"] == "MEDIUM"


class TestVulnerabilityRecord:
    def test_id_auto_generated(self):
        r1 = VulnerabilityRecord(source="test", asset="host", cve_id="CVE-1", severity="LOW")
        r2 = VulnerabilityRecord(source="test", asset="host", cve_id="CVE-1", severity="LOW")
        assert r1.id != r2.id

    def test_ingested_at_set(self):
        r = VulnerabilityRecord(source="test", asset="host", cve_id="CVE-1", severity="LOW")
        assert r.ingested_at is not None
        # Should be parseable as ISO datetime
        datetime.fromisoformat(r.ingested_at)

    def test_default_status_is_new(self):
        r = VulnerabilityRecord(source="test", asset="host", cve_id="CVE-1", severity="LOW")
        assert r.status == "new"


# ─── Enrichment tests ─────────────────────────────────────────────────────────

class TestSLADeadlines:
    def test_critical_sla_is_1_day(self):
        base = datetime.utcnow()
        deadline = compute_sla_deadline("CRITICAL", base.isoformat())
        diff = deadline - base
        assert diff.days == 1

    def test_high_sla_is_7_days(self):
        base = datetime.utcnow()
        deadline = compute_sla_deadline("HIGH", base.isoformat())
        assert deadline - base == timedelta(days=7)

    def test_medium_sla_is_30_days(self):
        base = datetime.utcnow()
        deadline = compute_sla_deadline("MEDIUM", base.isoformat())
        assert deadline - base == timedelta(days=30)

    def test_low_sla_is_90_days(self):
        base = datetime.utcnow()
        deadline = compute_sla_deadline("LOW", base.isoformat())
        assert deadline - base == timedelta(days=90)

    def test_unknown_defaults_to_90_days(self):
        base = datetime.utcnow()
        deadline = compute_sla_deadline("UNKNOWN", base.isoformat())
        assert deadline - base == timedelta(days=90)


class TestNVDFetch:
    @patch("worker.requests.get")
    def test_successful_fetch(self, mock_get):
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            "vulnerabilities": [{
                "cve": {
                    "metrics": {
                        "cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "vectorString": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]
                    },
                    "descriptions": [{"lang": "en", "value": "Critical RCE vulnerability"}]
                }
            }]
        }
        result = fetch_nvd_data("CVE-2023-38408")
        assert result["cvss_score"] == 9.8
        assert "Critical RCE" in result["description"]

    @patch("worker.requests.get")
    def test_handles_404(self, mock_get):
        mock_get.return_value.status_code = 404
        result = fetch_nvd_data("CVE-9999-99999")
        assert result == {}

    @patch("worker.requests.get")
    def test_handles_timeout(self, mock_get):
        import requests as req
        mock_get.side_effect = req.exceptions.Timeout()
        result = fetch_nvd_data("CVE-2023-00001")
        assert result == {}


class TestEPSSFetch:
    @patch("worker.requests.get")
    def test_successful_fetch(self, mock_get):
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            "data": [{"cve": "CVE-2023-44487", "epss": "0.9456", "percentile": "0.9998"}]
        }
        result = fetch_epss_score("CVE-2023-44487")
        assert abs(result["epss_score"] - 0.9456) < 0.0001
        assert abs(result["epss_percentile"] - 0.9998) < 0.0001

    @patch("worker.requests.get")
    def test_empty_data_returns_empty(self, mock_get):
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {"data": []}
        result = fetch_epss_score("CVE-0000-00000")
        assert result == {}


# ─── AI Prioritizer tests ──────────────────────────────────────────────────────

class TestHeuristicScoring:
    def _make_prompt(self, cvss, epss):
        return f"CVSS Score: {cvss}\nEPSS Score: {epss} (probability)\nSeverity: HIGH"

    def test_high_cvss_high_epss_is_critical(self):
        result = _heuristic_score_fallback(self._make_prompt(9.5, 0.85))
        assert result["risk_tier"] == "CRITICAL"
        assert result["risk_score"] >= 90

    def test_medium_cvss_low_epss_is_high(self):
        result = _heuristic_score_fallback(self._make_prompt(7.5, 0.1))
        assert result["risk_tier"] == "HIGH"

    def test_low_cvss_low_epss_is_medium(self):
        result = _heuristic_score_fallback(self._make_prompt(4.5, 0.01))
        assert result["risk_tier"] == "MEDIUM"

    def test_very_low_is_low(self):
        result = _heuristic_score_fallback(self._make_prompt(2.0, 0.001))
        assert result["risk_tier"] == "LOW"

    def test_returns_remediation_steps(self):
        result = _heuristic_score_fallback(self._make_prompt(8.0, 0.5))
        assert isinstance(result["remediation_steps"], list)
        assert len(result["remediation_steps"]) > 0

    def test_returns_compensating_controls(self):
        result = _heuristic_score_fallback(self._make_prompt(8.0, 0.5))
        assert "compensating_controls" in result
        assert len(result["compensating_controls"]) > 0


class TestAIPromptStructure:
    def test_prompt_contains_all_required_fields(self):
        prompt = AI_SCORING_PROMPT.format(
            cve_id="CVE-2023-44487",
            severity="HIGH",
            cvss_score=7.5,
            cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            epss_score=0.9456,
            epss_percentile=0.9998,
            package="nghttp2",
            installed_version="1.43.0-1",
            fixed_version="1.43.0-1+deb11u1",
            asset="nginx:1.23",
            description="HTTP/2 Rapid Reset Attack",
        )
        assert "CVE-2023-44487" in prompt
        assert "EPSS" in prompt
        assert "risk_tier" in prompt
        assert "remediation_steps" in prompt
        assert "compensating_controls" in prompt
        assert "JSON" in prompt

    def test_score_vulnerability_uses_fallback_without_api_key(self):
        vuln = {
            "cve_id": "CVE-2023-44487",
            "severity": "HIGH",
            "cvss_score": 7.5,
            "epss_score": 0.9456,
            "epss_percentile": 0.9998,
            "package": "nghttp2",
            "installed_version": "1.43.0-1",
            "fixed_version": "1.43.0-1+deb11u1",
            "asset": "nginx:1.23",
            "description": "HTTP/2 Rapid Reset",
        }
        # With no API key, should use heuristic
        with patch("main.OPENAI_API_KEY", ""):
            result = score_vulnerability(vuln)
        assert "risk_tier" in result
        assert result["risk_tier"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")


# ─── Integration test ─────────────────────────────────────────────────────────

class TestEndToEndFlow:
    def test_trivy_to_records_to_sla(self):
        """Simulate full ingest → normalize → SLA pipeline."""
        records = parse_trivy_json(TRIVY_SAMPLE)
        assert len(records) == 2

        critical = next(r for r in records if r.severity == "CRITICAL")
        deadline = compute_sla_deadline(critical.severity, critical.ingested_at)
        diff = deadline - datetime.fromisoformat(critical.ingested_at)
        assert diff.days == 1

        high = next(r for r in records if r.severity == "HIGH")
        deadline = compute_sla_deadline(high.severity, high.ingested_at)
        diff = deadline - datetime.fromisoformat(high.ingested_at)
        assert diff.days == 7
