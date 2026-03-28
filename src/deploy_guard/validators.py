"""Mathematical validators for document numbers and card numbers."""


def cpf_valid(cpf_digits: str) -> bool:
    """Valida CPF pelo algoritmo módulo 11 (dígitos verificadores)."""
    d = [int(c) for c in cpf_digits if c.isdigit()]
    if len(d) != 11:
        return False
    if len(set(d)) == 1:
        return False
    s = sum(d[i] * (10 - i) for i in range(9))
    r = (s * 10) % 11
    if r == 10:
        r = 0
    if r != d[9]:
        return False
    s = sum(d[i] * (11 - i) for i in range(10))
    r = (s * 10) % 11
    if r == 10:
        r = 0
    return r == d[10]


def cnpj_valid(cnpj_digits: str) -> bool:
    """Valida CNPJ pelo algoritmo oficial."""
    d = [int(c) for c in cnpj_digits if c.isdigit()]
    if len(d) != 14:
        return False
    if len(set(d)) == 1:
        return False
    weights1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    weights2 = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    s = sum(d[i] * weights1[i] for i in range(12))
    r = s % 11
    v1 = 0 if r < 2 else 11 - r
    if v1 != d[12]:
        return False
    s = sum(d[i] * weights2[i] for i in range(13))
    r = s % 11
    v2 = 0 if r < 2 else 11 - r
    return v2 == d[13]


def luhn_valid(number: str) -> bool:
    """Valida número de cartão pelo algoritmo de Luhn."""
    digits = [int(c) for c in number if c.isdigit()]
    if len(digits) < 13:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0
