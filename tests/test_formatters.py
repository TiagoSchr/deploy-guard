"""Tests for output formatters (JSON, SARIF, HTML)."""

import json
import pytest
from deploy_guard.models import Issue
from deploy_guard.formatters.json_fmt import json_report
from deploy_guard.formatters.sarif import sarif_report
from deploy_guard.formatters.html import html_report


@pytest.fixture
def sample_issues():
    return [
        Issue(
            file="test.js", line=10,
            type="CREDENCIAL — Stripe Secret Key (live)",
            risk_level="critical", confidence="high",
            impact="crítico (comprometimento direto)",
            decision="BLOCK",
            message="Stripe Secret Key detectado.",
            suggestion="Usar variáveis de ambiente.",
            rule_id="secret-detected",
            revoke_required=True, notify_dpo=False,
        ),
        Issue(
            file="test.sql", line=5,
            type="DADOS PESSOAIS — CPF (LGPD Art. 5, I)",
            risk_level="critical", confidence="high",
            impact="crítico — dado pessoal identificável",
            decision="BLOCK",
            message="CPF válido detectado.",
            suggestion="Remover dado real.",
            rule_id="lgpd-cpf-formatted",
            revoke_required=False, notify_dpo=True,
        ),
    ]


class TestJSONReport:
    def test_valid_json(self, sample_issues):
        output = json_report(sample_issues, "./test")
        data = json.loads(output)
        assert "summary" in data
        assert "issues" in data

    def test_decision_is_block(self, sample_issues):
        data = json.loads(json_report(sample_issues, "./test"))
        assert data["summary"]["decision"] == "block"

    def test_issue_count(self, sample_issues):
        data = json.loads(json_report(sample_issues, "./test"))
        assert data["summary"]["total_issues"] == 2

    def test_empty_issues(self):
        data = json.loads(json_report([], "./test"))
        assert data["summary"]["decision"] == "allow"
        assert data["summary"]["total_issues"] == 0


class TestSARIFReport:
    def test_valid_sarif(self, sample_issues):
        output = sarif_report(sample_issues, "./test")
        data = json.loads(output)
        assert data["version"] == "2.1.0"
        assert "$schema" in data

    def test_has_results(self, sample_issues):
        data = json.loads(sarif_report(sample_issues, "./test"))
        results = data["runs"][0]["results"]
        assert len(results) == 2

    def test_has_rules(self, sample_issues):
        data = json.loads(sarif_report(sample_issues, "./test"))
        rules = data["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) > 0

    def test_empty_sarif(self):
        data = json.loads(sarif_report([], "./test"))
        assert data["runs"][0]["results"] == []


class TestHTMLReport:
    def test_valid_html(self, sample_issues):
        output = html_report(sample_issues, "./test")
        assert "<!DOCTYPE html>" in output
        assert "Deploy Guard" in output

    def test_contains_issues(self, sample_issues):
        output = html_report(sample_issues, "./test")
        assert "Stripe" in output
        assert "CPF" in output

    def test_blocked_banner(self, sample_issues):
        output = html_report(sample_issues, "./test")
        assert "BLOCKED" in output

    def test_clean_report(self):
        output = html_report([], "./test")
        assert "PASSED" in output
        assert "No security issues found" in output
