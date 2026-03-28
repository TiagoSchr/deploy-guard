"""Tests for the core scanning engine using the 7 test scenarios."""

import os
import pytest
from pathlib import Path

from deploy_guard.scanner import DeployGuard
from deploy_guard.models import Issue, final_decision, deduplicate

TESTS_DIR = Path(__file__).parent


class TestScenario1GitHubActions:
    """Scenario 1: Insecure GitHub Actions workflow with hardcoded secrets."""

    @pytest.fixture
    def issues(self):
        guard = DeployGuard(target="any")
        return guard.scan_path(str(TESTS_DIR / "scenario-1-github-actions.yml"))

    def test_blocks_deploy(self, issues):
        assert final_decision(issues) == "block"

    def test_detects_aws_key(self, issues):
        aws = [i for i in issues if "AWS" in i.type]
        assert len(aws) > 0

    def test_detects_stripe_key(self, issues):
        creds = [i for i in issues if "credencial" in i.type.lower() or "SendGrid" in i.type]
        assert len(creds) > 0

    def test_detects_connection_string(self, issues):
        conn = [i for i in issues if "Connection String" in i.type]
        assert len(conn) > 0

    def test_detects_env_exposure(self, issues):
        env_exp = [i for i in issues if "env" in i.message.lower() or "vari" in i.type.lower()]
        assert len(env_exp) > 0

    def test_has_critical_issues(self, issues):
        critical = [i for i in issues if i.risk_level == "critical"]
        assert len(critical) >= 2


class TestScenario2VercelNextJS:
    """Scenario 2: Misconfigured Next.js .env file."""

    @pytest.fixture
    def issues(self):
        guard = DeployGuard(target="frontend")
        return guard.scan_path(str(TESTS_DIR / "scenario-2-vercel-nextjs.env"))

    def test_blocks_deploy(self, issues):
        assert final_decision(issues) == "block"

    def test_detects_public_secrets(self, issues):
        frontend = [i for i in issues if "NEXT_PUBLIC" in i.type or "NEXT_PUBLIC" in i.message]
        assert len(frontend) > 0

    def test_detects_frontend_exposure(self, issues):
        frontend = [i for i in issues if "FRONTEND" in i.type or "EXPOSIÇÃO" in i.type]
        assert len(frontend) > 0


class TestScenario3AWSTerraform:
    """Scenario 3: Terraform with hardcoded secrets and misconfigurations."""

    @pytest.fixture
    def issues(self):
        guard = DeployGuard(target="iac")
        return guard.scan_path(str(TESTS_DIR / "scenario-3-aws-terraform.tf"))

    def test_blocks_deploy(self, issues):
        assert final_decision(issues) == "block"

    def test_detects_publicly_accessible(self, issues):
        pub = [i for i in issues if "publicly_accessible" in i.message]
        assert len(pub) > 0

    def test_detects_insecure_config(self, issues):
        configs = [i for i in issues if "CONFIGURA" in i.type or "insecure" in i.rule_id]
        assert len(configs) > 0

    def test_detects_s3_public(self, issues):
        s3 = [i for i in issues if "S3" in i.type]
        assert len(s3) > 0


class TestScenario4DockerCompose:
    """Scenario 4: Docker Compose with exposed credentials."""

    @pytest.fixture
    def issues(self):
        guard = DeployGuard(target="any")
        return guard.scan_path(str(TESTS_DIR / "scenario-4-docker-compose.yml"))

    def test_blocks_deploy(self, issues):
        assert final_decision(issues) == "block"

    def test_detects_debug_enabled(self, issues):
        debug = [i for i in issues if "DEBUG" in i.type]
        assert len(debug) > 0

    def test_detects_hardcoded_passwords(self, issues):
        creds = [i for i in issues if "credencial" in i.type.lower() or "CREDENCIAL" in i.type]
        assert len(creds) > 0


class TestScenario5FrontendBundle:
    """Scenario 5: Frontend bundle with embedded secrets and PII."""

    @pytest.fixture
    def issues(self):
        guard = DeployGuard(target="frontend")
        return guard.scan_path(str(TESTS_DIR / "scenario-5-frontend-bundle.js"))

    def test_blocks_deploy(self, issues):
        assert final_decision(issues) == "block"

    def test_detects_credential(self, issues):
        creds = [i for i in issues if "credencial" in i.type.lower() or "CREDENCIAL" in i.type]
        assert len(creds) > 0

    def test_detects_cpf(self, issues):
        cpf = [i for i in issues if "CPF" in i.type]
        assert len(cpf) > 0

    def test_detects_debug_active(self, issues):
        debug = [i for i in issues if "DEBUG" in i.type]
        assert len(debug) > 0


class TestScenario6CleanBackend:
    """Scenario 6: Secure backend code — should PASS."""

    @pytest.fixture
    def issues(self):
        guard = DeployGuard(target="backend")
        return guard.scan_path(str(TESTS_DIR / "scenario-6-clean-backend.js"))

    def test_allows_deploy(self, issues):
        decision = final_decision(issues)
        assert decision in ("allow", "warn"), \
            f"Clean backend should pass, got: {decision} with {len(issues)} issues"

    def test_no_critical_issues(self, issues):
        critical = [i for i in issues if i.risk_level == "critical"]
        assert len(critical) == 0, \
            f"Clean backend should have no critical issues, found: {[i.type for i in critical]}"


class TestScenario7ProductionDump:
    """Scenario 7: Production SQL dump with real PII."""

    @pytest.fixture
    def issues(self):
        guard = DeployGuard(target="any", strict_lgpd=True)
        return guard.scan_path(str(TESTS_DIR / "scenario-7-production-dump.sql"))

    def test_blocks_deploy(self, issues):
        assert final_decision(issues) == "block"

    def test_detects_sql_artifact(self, issues):
        artifact = [i for i in issues if "ARTEFATO" in i.type]
        assert len(artifact) > 0

    def test_detects_cpf(self, issues):
        cpf = [i for i in issues if "CPF" in i.type]
        assert len(cpf) > 0

    def test_detects_emails(self, issues):
        email = [i for i in issues if "Email" in i.type]
        assert len(email) > 0

    def test_requires_dpo_notification(self, issues):
        dpo = [i for i in issues if i.notify_dpo]
        assert len(dpo) > 0
