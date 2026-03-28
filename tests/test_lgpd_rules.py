"""Tests for LGPD-specific detection rules."""

import pytest
from deploy_guard.scanner import DeployGuard
from deploy_guard.models import final_decision


def scan_line(line: str, ext: str = ".txt", target: str = "any",
              strict_lgpd: bool = False) -> list:
    """Helper: scan a single line and return issues."""
    guard = DeployGuard(target=target, strict_lgpd=strict_lgpd)
    guard._scan_lgpd([line], "test.txt", ext, line)
    return guard.issues


def scan_lines(lines: list[str], ext: str = ".txt", target: str = "any") -> list:
    """Helper: scan multiple lines."""
    guard = DeployGuard(target=target)
    guard._scan_lgpd(lines, "test.txt", ext, "\n".join(lines))
    return guard.issues


class TestCPFDetection:
    """CPF detection matching the lgpd-tests.yml spec."""

    def test_cpf_formatted_blocks(self):
        """test-cpf-01: CPF real with punctuation → BLOCK"""
        issues = scan_line('cpf: "529.982.247-25"')
        assert any(i.decision == "BLOCK" and "CPF" in i.type for i in issues)

    def test_cpf_dummy_allows(self):
        """test-cpf-03: Dummy CPF → ALLOW"""
        issues = scan_line('exemplo: "000.000.000-00"')
        cpf_issues = [i for i in issues if "CPF" in i.type]
        assert len(cpf_issues) == 0

    def test_cpf_all_same_allows(self):
        """test-cpf-04: All same digits → ALLOW"""
        issues = scan_line('"cpf": "11111111111"')
        cpf_issues = [i for i in issues if "CPF" in i.type]
        assert len(cpf_issues) == 0


class TestCNPJDetection:
    def test_cnpj_valid_blocks(self):
        """test-cnpj-01: Real CNPJ → BLOCK"""
        issues = scan_line('supplier_cnpj = "11.222.333/0001-81"')
        assert any(i.decision == "BLOCK" and "CNPJ" in i.type for i in issues)

    def test_cnpj_dummy_allows(self):
        """test-cnpj-02: All-zeros CNPJ → ALLOW"""
        issues = scan_line('exemplo: "00.000.000/0000-00"')
        cnpj_issues = [i for i in issues if "CNPJ" in i.type]
        assert len(cnpj_issues) == 0


class TestEmailDetection:
    def test_real_email_warns(self):
        """test-email-01: Real email → WARN"""
        issues = scan_line('user_email = "joao.silva@empresa.com.br"')
        assert any(i.decision == "WARN" and "Email" in i.type for i in issues)

    def test_email_in_sql_blocks(self):
        """test-email-02: Email in SQL → BLOCK"""
        issues = scan_line(
            "INSERT INTO clientes (email) VALUES ('maria@empresa.com')",
            ext=".sql"
        )
        assert any(i.decision == "BLOCK" and "Email" in i.type for i in issues)

    def test_example_email_allows(self):
        """test-email-03: example.com email → ALLOW"""
        issues = scan_line('to: "user@example.com"')
        email_issues = [i for i in issues if "Email" in i.type]
        assert len(email_issues) == 0

    def test_noreply_allows(self):
        """test-email-04: noreply email → ALLOW"""
        issues = scan_line('sender = "noreply@empresa.com"')
        email_issues = [i for i in issues if "Email" in i.type]
        assert len(email_issues) == 0


class TestPhoneDetection:
    def test_br_phone_warns(self):
        """test-phone-01: Brazilian phone with DDD → WARN"""
        issues = scan_line('telefone: "+55 11 99999-8888"')
        assert any("Telefone" in i.type for i in issues)

    def test_placeholder_allows(self):
        """test-phone-03: Placeholder phone → ALLOW"""
        issues = scan_line('telefone: "(00) 00000-0000"')
        phone_issues = [i for i in issues if "Telefone" in i.type]
        assert len(phone_issues) == 0


class TestCreditCardDetection:
    def test_valid_card_blocks(self):
        """test-card-01: Valid Luhn card → BLOCK"""
        issues = scan_line('card_number = "4532015112830366"')
        assert any(i.decision == "BLOCK" and "Cartão" in i.type for i in issues)

    def test_stripe_test_card_allows(self):
        """test-card-02: Stripe test card → ALLOW"""
        issues = scan_line('test_card = "4111111111111111"')
        card_issues = [i for i in issues if "Cartão" in i.type]
        assert len(card_issues) == 0


class TestCVVDetection:
    def test_cvv_in_context_blocks(self):
        """test-cvv-01: Explicit CVV field → BLOCK"""
        issues = scan_line('cvv: "372"')
        assert any(i.decision == "BLOCK" and "CVV" in i.type for i in issues)


class TestHealthDataDetection:
    def test_diagnosis_blocks(self):
        """test-health-01: Health diagnosis → BLOCK"""
        issues = scan_line('diagnostico: "F32.0"')
        assert any(i.decision == "BLOCK" and "Saúde" in i.type for i in issues)


class TestCSVHeaderDetection:
    def test_csv_with_pii_headers_blocks(self):
        """test-csv-01: CSV with PII columns → BLOCK"""
        issues = scan_line("nome,cpf,email,telefone,nascimento", ext=".csv")
        assert any(i.decision == "BLOCK" and "CSV" in i.type for i in issues)
