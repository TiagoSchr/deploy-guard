"""Tests for mathematical validators (CPF, CNPJ, Luhn)."""

import pytest
from deploy_guard.validators import cpf_valid, cnpj_valid, luhn_valid


class TestCPFValidator:
    """CPF validation algorithm tests."""

    def test_valid_cpf(self):
        assert cpf_valid("12345678909") is True

    def test_invalid_cpf_wrong_digits(self):
        assert cpf_valid("12345678900") is False

    def test_all_same_digits(self):
        """CPFs with all identical digits are invalid."""
        for d in range(10):
            assert cpf_valid(str(d) * 11) is False

    def test_too_short(self):
        assert cpf_valid("123456789") is False

    def test_too_long(self):
        assert cpf_valid("123456789012") is False

    def test_formatted_stripped(self):
        # Strip formatting before validating
        raw = "123.456.789-09".replace(".", "").replace("-", "")
        assert cpf_valid(raw) is True

    def test_empty_string(self):
        assert cpf_valid("") is False


class TestCNPJValidator:
    """CNPJ validation algorithm tests."""

    def test_valid_cnpj(self):
        assert cnpj_valid("11222333000181") is True

    def test_invalid_cnpj(self):
        assert cnpj_valid("11222333000100") is False

    def test_all_same_digits(self):
        for d in range(10):
            assert cnpj_valid(str(d) * 14) is False

    def test_too_short(self):
        assert cnpj_valid("1122233300018") is False

    def test_empty_string(self):
        assert cnpj_valid("") is False


class TestLuhnValidator:
    """Credit card Luhn algorithm tests."""

    def test_visa_test_card(self):
        assert luhn_valid("4111111111111111") is True

    def test_mastercard_test(self):
        assert luhn_valid("5500000000000004") is True

    def test_amex_test(self):
        assert luhn_valid("378282246310005") is True

    def test_invalid_card(self):
        assert luhn_valid("4111111111111112") is False

    def test_too_short(self):
        assert luhn_valid("411111") is False

    def test_empty(self):
        assert luhn_valid("") is False
