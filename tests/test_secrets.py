"""Tests for secret detection patterns."""

import pytest
from deploy_guard.scanner import DeployGuard


def scan_line(line: str) -> list:
    guard = DeployGuard(target="any")
    guard._scan_secrets([line], "test.txt")
    return guard.issues


class TestAWSSecrets:
    def test_detects_aws_access_key(self):
        issues = scan_line('AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE')
        assert any("AWS" in i.type for i in issues)

    def test_detects_aws_key_in_yaml(self):
        issues = scan_line('  aws_access_key_id: AKIAIOSFODNN7EXAMPLE')
        assert any("AWS" in i.type for i in issues)


class TestStripeSecrets:
    def test_detects_live_key(self):
        prefix = 'sk_' + 'live_'
        issues = scan_line('STRIPE_KEY=' + prefix + 'abcdefghijklmnopqrstuvwx')
        assert any("Stripe" in i.type and "live" in i.type for i in issues)

    def test_detects_test_key(self):
        prefix = 'sk_' + 'test_'
        issues = scan_line('STRIPE_KEY=' + prefix + 'abcdefghijklmnopqrstuvwx')
        assert any("Stripe" in i.type and "test" in i.type.lower() for i in issues)


class TestOpenAISecrets:
    def test_detects_project_key(self):
        issues = scan_line('OPENAI_KEY=sk-proj-' + 'a' * 48)
        assert any("OpenAI" in i.type for i in issues)


class TestSendGridSecrets:
    def test_detects_sendgrid_key(self):
        key = 'SG.' + 'a' * 22 + '.' + 'b' * 43
        issues = scan_line(f'SENDGRID_KEY={key}')
        assert any("SendGrid" in i.type for i in issues)


class TestGitHubSecrets:
    def test_detects_pat(self):
        issues = scan_line('TOKEN=ghp_' + 'a' * 36)
        assert any("GitHub" in i.type for i in issues)


class TestConnectionStrings:
    def test_detects_postgres(self):
        issues = scan_line('DATABASE_URL=postgresql://admin:secret@localhost:5432/db')
        assert any("Connection String" in i.type for i in issues)

    def test_detects_mongodb(self):
        issues = scan_line('MONGO_URI=mongodb://root:pass@cluster.mongodb.net/db')
        assert any("Connection String" in i.type for i in issues)


class TestPrivateKeys:
    def test_detects_rsa_key(self):
        issues = scan_line('-----BEGIN RSA PRIVATE KEY-----')
        assert any("Chave Privada" in i.type or "PRIVATE KEY" in i.type for i in issues)

    def test_detects_generic_key(self):
        issues = scan_line('-----BEGIN PRIVATE KEY-----')
        assert any("Chave Privada" in i.type or "PRIVATE KEY" in i.type for i in issues)


class TestGenericCredentials:
    def test_detects_hardcoded_password(self):
        issues = scan_line('password = "S3cr3tP@ssw0rd!"')
        assert any("credencial" in i.type.lower() for i in issues)

    def test_ignores_placeholder(self):
        issues = scan_line('password = "changeme"')
        cred_issues = [i for i in issues if "credencial" in i.type.lower()]
        assert len(cred_issues) == 0
