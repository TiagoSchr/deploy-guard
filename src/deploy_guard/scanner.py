"""Core scanning engine for Deploy Guard."""

import re
import base64
from pathlib import Path
from typing import Optional

from .models import Issue
from .validators import cpf_valid, cnpj_valid, luhn_valid
from .known_safe import (
    SAFE_CPF_PATTERNS, SAFE_PHONES, KNOWN_TEST_CARDS,
    BR_NAMES_COMMON, email_is_safe,
)
from .patterns import (
    SECRET_PATTERNS, INSECURE_CONFIG_PATTERNS,
    ARTIFACT_EXTENSIONS_HIGH, ARTIFACT_EXTENSIONS_CRITICAL,
    ARTIFACT_EXTENSIONS_WARN, FRONTEND_ENV_PATTERNS,
)


def _decode_jwt_payload(token: str) -> Optional[str]:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    payload = parts[1]
    payload += "=" * (4 - len(payload) % 4)
    try:
        return base64.urlsafe_b64decode(payload).decode("utf-8", errors="ignore")
    except Exception:
        return None


def _contains_pii(text: str) -> bool:
    patterns = [
        r'\d{3}\.\d{3}\.\d{3}-\d{2}',
        r'"cpf"\s*:', r'"telefone"\s*:',
        r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b',
        r'"rg"\s*:', r'"nascimento"\s*:',
    ]
    return any(re.search(p, text, re.IGNORECASE) for p in patterns)


def ext_is_frontend(filepath: str) -> bool:
    return Path(filepath).suffix.lower() in {
        ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".vue", ".svelte"
    }


class DeployGuard:
    def __init__(self, target: str = "any", strict_lgpd: bool = False,
                 scan_pdf_enabled: bool = False):
        self.target = target
        self.strict_lgpd = strict_lgpd
        self.scan_pdf_enabled = scan_pdf_enabled
        self.issues: list[Issue] = []

    def scan_path(self, path: str) -> list[Issue]:
        p = Path(path)
        if p.is_file():
            self._scan_file(p)
        elif p.is_dir():
            for f in p.rglob("*"):
                if f.is_file() and not self._should_skip(f):
                    self._scan_file(f)
        return self.issues

    def _should_skip(self, path: Path) -> bool:
        skip_dirs = {".git", "node_modules", "__pycache__", ".venv", "venv"}
        return any(part in skip_dirs for part in path.parts)

    def _scan_file(self, path: Path):
        ext = path.suffix.lower()
        name = path.name.lower()

        # PDF
        if ext == ".pdf" and self.scan_pdf_enabled:
            from .pdf_scanner import scan_pdf
            self.issues.extend(scan_pdf(str(path), self))
            return

        # Artefatos críticos
        if ext in ARTIFACT_EXTENSIONS_CRITICAL:
            self.issues.append(Issue(
                file=str(path), line=0,
                type="ARTEFATO INDEVIDO",
                risk_level="critical", confidence="high",
                impact="crítico — dump/backup incluído no artefato de deploy",
                decision="BLOCK",
                message=f"Arquivo {ext} detectado. Dumps e backups não devem estar no repositório ou build.",
                suggestion="Remover do repositório. Usar git rm e reescrever histórico se já foi commitado.",
                rule_id="artifact-critical", notify_dpo=True
            ))

        if ext in ARTIFACT_EXTENSIONS_HIGH:
            self.issues.append(Issue(
                file=str(path), line=0,
                type="ARTEFATO INDEVIDO — Chave/Certificado",
                risk_level="critical", confidence="high",
                impact="crítico — chave privada ou certificado exposto",
                decision="BLOCK",
                message=f"Arquivo {name} ({ext}) é uma chave privada ou certificado. Nunca versionar.",
                suggestion="Remover imediatamente. Usar cert-manager, ACM ou variável de ambiente para certificados.",
                rule_id="artifact-key", revoke_required=True
            ))
            return

        if ext in ARTIFACT_EXTENSIONS_WARN:
            self.issues.append(Issue(
                file=str(path), line=0,
                type="ARTEFATO SUSPEITO",
                risk_level="high", confidence="medium",
                impact="alto impacto — planilha/log pode conter dados pessoais",
                decision="WARN",
                message=f"Arquivo {ext} detectado no artefato. Verificar se contém dados pessoais reais.",
                suggestion="Remover do build. Se necessário, confirmar ausência de PII antes de publicar.",
                rule_id="artifact-warn", notify_dpo=True
            ))

        # Ler conteúdo
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return

        lines = content.splitlines()
        self._scan_secrets(lines, str(path))
        self._scan_insecure_config(lines, str(path))
        self._scan_lgpd(lines, str(path), ext, content)
        if self.target == "frontend" or ext in {".js", ".ts", ".jsx", ".tsx", ".mjs"}:
            self._scan_frontend(lines, str(path))
        if ext in {".yml", ".yaml", ".env", ".env.local", ".env.production"}:
            self._scan_env_vars(lines, str(path))

    def _scan_secrets(self, lines: list[str], filepath: str):
        for i, line in enumerate(lines, 1):
            for pattern, name, risk, revoke in SECRET_PATTERNS:
                m = re.search(pattern, line, re.IGNORECASE)
                if m:
                    if "JWT" in name:
                        payload = _decode_jwt_payload(m.group(0))
                        if payload and _contains_pii(payload):
                            self.issues.append(Issue(
                                file=filepath, line=i,
                                type="CREDENCIAL — JWT com PII no payload",
                                risk_level="critical", confidence="high",
                                impact="crítico — dados pessoais em token JWT",
                                decision="BLOCK",
                                message="JWT com dados pessoais (CPF, email, etc.) no payload. Viola LGPD.",
                                suggestion="JWTs devem conter apenas IDs opacos (sub, exp, iat). Mover PII para server-side.",
                                rule_id="lgpd-jwt-pii", notify_dpo=True
                            ))
                        else:
                            self.issues.append(Issue(
                                file=filepath, line=i,
                                type="CREDENCIAL — JWT hardcoded",
                                risk_level="medium", confidence="medium",
                                impact="médio impacto — token hardcoded pode conter dados sensíveis",
                                decision="WARN",
                                message="JWT hardcoded detectado. Verificar se o payload contém dados pessoais.",
                                suggestion="Não hardcodar tokens. Usar variáveis de ambiente ou geração dinâmica.",
                                rule_id="secret-jwt"
                            ))
                        continue

                    if "Possível credencial" in name:
                        val_match = re.search(r'[=:]\s*["\']([^"\']+)["\']', line)
                        val = val_match.group(1) if val_match else ""
                        if len(set(val)) <= 3 or val.lower() in {
                            "password", "secret", "changeme", "your_key", "xxx", "placeholder"
                        }:
                            continue

                    decision = "BLOCK"
                    impact_text = ("crítico (comprometimento direto)" if risk == "critical"
                                   else "alto impacto (exposição real)")
                    self.issues.append(Issue(
                        file=filepath, line=i,
                        type=f"CREDENCIAL — {name}",
                        risk_level=risk, confidence="high",
                        impact=impact_text, decision=decision,
                        message=f"{name} detectado hardcoded na linha {i}.",
                        suggestion="Usar variáveis de ambiente ou secret manager. Revogar a credencial atual.",
                        rule_id="secret-detected", revoke_required=revoke
                    ))

    def _scan_insecure_config(self, lines: list[str], filepath: str):
        content_block = "\n".join(lines)
        for pattern, name, risk, suggestion in INSECURE_CONFIG_PATTERNS:
            m = re.search(pattern, content_block, re.IGNORECASE | re.MULTILINE)
            if m:
                line_num = content_block[:m.start()].count("\n") + 1
                self.issues.append(Issue(
                    file=filepath, line=line_num,
                    type=f"CONFIGURAÇÃO INSEGURA — {name}",
                    risk_level=risk, confidence="high",
                    impact=("alto impacto (exposição de infraestrutura ou dados)"
                            if risk in ("high", "critical") else "médio impacto"),
                    decision="BLOCK" if risk == "critical" else "WARN",
                    message=f"{name} detectado em {Path(filepath).name}.",
                    suggestion=suggestion, rule_id="insecure-config"
                ))

    def _scan_lgpd(self, lines: list[str], filepath: str, ext: str, content: str):
        cpf_re = re.compile(r'\b(\d{3})\.(\d{3})\.(\d{3})-(\d{2})\b')
        cpf_raw_re = re.compile(r'\b(\d{11})\b')
        cpf_context_re = re.compile(
            r'(?:cpf|tax_id|national_id|doc_number|fiscal|documento)', re.IGNORECASE
        )
        cnpj_re = re.compile(r'\b(\d{2})\.(\d{3})\.(\d{3})/(\d{4})-(\d{2})\b')
        email_re = re.compile(r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b')
        phone_re = re.compile(
            r'\b(?:\+55\s?)?(?:\(?\d{2}\)?\s?)(?:9\d{4}[\s\-]?\d{4}|\d{4}[\s\-]?\d{4})\b'
        )
        phone_context_re = re.compile(
            r'(?:phone|telefone|celular|fone|mobile|whatsapp|tel\b)', re.IGNORECASE
        )
        card_re = re.compile(
            r'\b(?:4[0-9]{3}|5[1-5][0-9]{2}|3[47][0-9]{2}|6(?:011|5[0-9]{2}))'
            r'[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?(?:[0-9]{4}|[0-9]{5})\b'
        )
        cvv_context_re = re.compile(
            r'(?:cvv|cvc|csc|security_code|codigo_seguranca)', re.IGNORECASE
        )
        cvv_val_re = re.compile(r'\b\d{3,4}\b')
        health_re = re.compile(
            r'(?:diagnostico|diagnóstico|cid_|cid10|prontuario|prontuário|'
            r'receita_medica|prescricao|prescrição|laudo|exame_resultado|'
            r'health_condition|medical_record|prescription)', re.IGNORECASE
        )

        for i, line in enumerate(lines, 1):
            context_window = " ".join(lines[max(0, i - 3):min(len(lines), i + 3)])

            # CPF formatado
            for m in cpf_re.finditer(line):
                raw = m.group(0).replace(".", "").replace("-", "")
                if raw in SAFE_CPF_PATTERNS:
                    continue
                if not cpf_valid(raw):
                    continue
                self.issues.append(Issue(
                    file=filepath, line=i,
                    type="DADOS PESSOAIS — CPF (LGPD Art. 5, I)",
                    risk_level="critical", confidence="high",
                    impact="crítico — dado pessoal identificável (CPF válido detectado)",
                    decision="BLOCK",
                    message=f"CPF válido detectado: {m.group(0)[:3]}.***.***-** — LGPD Art. 5, I.",
                    suggestion="Remover dado real. Em testes, usar CPF fictício inválido como 000.000.000-00.",
                    rule_id="lgpd-cpf-formatted", notify_dpo=True
                ))

            # CPF sem pontuação (só com contexto)
            if cpf_context_re.search(context_window):
                for m in cpf_raw_re.finditer(line):
                    raw = m.group(1)
                    if raw in SAFE_CPF_PATTERNS or len(set(raw)) == 1:
                        continue
                    if cpf_valid(raw):
                        self.issues.append(Issue(
                            file=filepath, line=i,
                            type="DADOS PESSOAIS — CPF sem formatação (LGPD Art. 5, I)",
                            risk_level="critical", confidence="medium",
                            impact="crítico — CPF válido em contexto de identificação",
                            decision="BLOCK",
                            message="Sequência de 11 dígitos válida como CPF em contexto de identificação.",
                            suggestion="Remover dado real. Usar anonimização ou IDs opacos.",
                            rule_id="lgpd-cpf-unformatted", notify_dpo=True
                        ))

            # CNPJ
            for m in cnpj_re.finditer(line):
                raw = re.sub(r'\D', '', m.group(0))
                if len(set(raw)) == 1:
                    continue
                if cnpj_valid(raw):
                    self.issues.append(Issue(
                        file=filepath, line=i,
                        type="DADOS PESSOAIS — CNPJ (LGPD Art. 5, I)",
                        risk_level="high", confidence="high",
                        impact="alto impacto — identificador de empresa real exposto",
                        decision="BLOCK",
                        message="CNPJ válido detectado. Pode indicar exposição de dado de parceiro/contrato.",
                        suggestion="Verificar se CNPJ real deveria estar neste arquivo. Usar fictício em testes.",
                        rule_id="lgpd-cnpj-formatted", notify_dpo=True
                    ))

            # Email
            for m in email_re.finditer(line):
                email = m.group(0).lower()
                if email_is_safe(email):
                    continue
                is_data_file = ext in {".sql", ".csv", ".tsv"}
                has_data_context = bool(re.search(
                    r'INSERT INTO|users|clientes|customers', context_window, re.IGNORECASE
                ))
                decision = "BLOCK" if (is_data_file or has_data_context) else "WARN"
                risk = "critical" if decision == "BLOCK" else "high"
                self.issues.append(Issue(
                    file=filepath, line=i,
                    type="DADOS PESSOAIS — Email (LGPD Art. 5, I)",
                    risk_level=risk, confidence="medium",
                    impact="alto impacto — endereço de email real de pessoa identificável",
                    decision=decision,
                    message=f"Email que parece ser de pessoa real detectado: {email[:4]}***@***",
                    suggestion="Usar placeholder (user@example.com). Dados reais de usuários nunca em código.",
                    rule_id="lgpd-email-real"
                ))

            # Telefone
            if phone_context_re.search(context_window):
                for m in phone_re.finditer(line):
                    digits = re.sub(r'\D', '', m.group(0))
                    if digits in SAFE_PHONES or len(set(digits)) <= 2:
                        continue
                    if len(digits) < 10:
                        continue
                    decision = "BLOCK" if ext in {".sql", ".csv"} else "WARN"
                    self.issues.append(Issue(
                        file=filepath, line=i,
                        type="DADOS PESSOAIS — Telefone BR (LGPD Art. 5, I)",
                        risk_level="high", confidence="medium",
                        impact="alto impacto — dado de contato pessoal",
                        decision=decision,
                        message="Número de telefone brasileiro detectado em contexto de dado pessoal.",
                        suggestion="Usar (00) 00000-0000 como placeholder em testes.",
                        rule_id="lgpd-phone-br"
                    ))

            # Cartão de crédito
            for m in card_re.finditer(line):
                raw = re.sub(r'\D', '', m.group(0))
                if raw in KNOWN_TEST_CARDS:
                    continue
                if luhn_valid(raw):
                    self.issues.append(Issue(
                        file=filepath, line=i,
                        type="DADOS FINANCEIROS — Cartão de Crédito/Débito (LGPD + PCI-DSS)",
                        risk_level="critical", confidence="high",
                        impact="crítico — PAN válido de cartão exposto",
                        decision="BLOCK",
                        message="Número de cartão de crédito/débito válido (Luhn) detectado.",
                        suggestion="Nunca armazenar PAN. Usar tokenização (Stripe, Braintree). Manter só últimos 4 dígitos.",
                        rule_id="lgpd-credit-card", notify_dpo=True
                    ))

            # CVV
            if cvv_context_re.search(line):
                for m in cvv_val_re.finditer(line):
                    val = m.group(0)
                    if len(val) in (3, 4) and len(set(val)) > 1:
                        self.issues.append(Issue(
                            file=filepath, line=i,
                            type="DADOS FINANCEIROS — CVV/CVC (LGPD + PCI-DSS)",
                            risk_level="critical", confidence="high",
                            impact="crítico — código de segurança de cartão exposto",
                            decision="BLOCK",
                            message="CVV/CVC detectado. Armazenar CVV viola PCI-DSS.",
                            suggestion="CVV nunca deve ser persistido. Processar e descartar imediatamente.",
                            rule_id="lgpd-card-cvv", notify_dpo=True
                        ))

            # Dados de saúde
            if health_re.search(line):
                self.issues.append(Issue(
                    file=filepath, line=i,
                    type="DADOS SENSÍVEIS — Saúde (LGPD Art. 5, II)",
                    risk_level="critical", confidence="medium",
                    impact="crítico — dado de saúde é categoria especialmente protegida",
                    decision="BLOCK",
                    message="Campo ou valor relacionado a dado de saúde detectado — LGPD Art. 11.",
                    suggestion="Dados de saúde requerem base legal específica. Nunca em logs ou artefatos públicos.",
                    rule_id="lgpd-health-data", notify_dpo=True
                ))

        # Nomes próprios brasileiros
        if ext in {".sql", ".csv", ".tsv", ".json"} and self.strict_lgpd:
            self._scan_br_names(lines, filepath)

        # CSV header
        if ext in {".csv", ".tsv"} and lines:
            header = lines[0].lower()
            pii_cols = {"cpf", "cnpj", "nome", "email", "telefone", "celular",
                        "nascimento", "rg", "cnh", "endereco", "endereço", "cep"}
            if any(col in header for col in pii_cols):
                self.issues.append(Issue(
                    file=filepath, line=1,
                    type="ARTEFATO INDEVIDO — CSV com PII (LGPD Art. 46)",
                    risk_level="critical", confidence="high",
                    impact="crítico — arquivo de dados pessoais em deploy",
                    decision="BLOCK",
                    message=f"CSV com colunas de dados pessoais: {header[:80]}",
                    suggestion="Remover do repositório/build. Dados de teste devem ser gerados com Faker.",
                    rule_id="lgpd-csv-with-pii", notify_dpo=True
                ))

    def _scan_frontend(self, lines: list[str], filepath: str):
        for i, line in enumerate(lines, 1):
            for pattern, name, risk in FRONTEND_ENV_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    self.issues.append(Issue(
                        file=filepath, line=i,
                        type=f"EXPOSIÇÃO FRONTEND — {name}",
                        risk_level=risk, confidence="high",
                        impact="crítico — variável de ambiente pública com dado sensível, exposta no browser",
                        decision="BLOCK",
                        message=f"{name} detectado em {Path(filepath).name}. "
                                "Prefixo NEXT_PUBLIC_/VITE_ injeta o valor diretamente no bundle JavaScript público.",
                        suggestion="Remover o prefixo público. Dado sensível deve ficar exclusivamente no backend.",
                        rule_id="frontend-public-secret"
                    ))

            for pattern, name, risk, revoke in SECRET_PATTERNS[:8]:
                m = re.search(pattern, line)
                if m and ext_is_frontend(filepath):
                    self.issues.append(Issue(
                        file=filepath, line=i,
                        type=f"CREDENCIAL EM FRONTEND — {name}",
                        risk_level="critical", confidence="high",
                        impact="crítico — credencial de API servida publicamente no browser",
                        decision="BLOCK",
                        message=f"{name} embutido em arquivo frontend ({Path(filepath).name}). "
                                "Visível para qualquer usuário via DevTools.",
                        suggestion="Remover completamente. Chamadas à API devem ser server-side ou via proxy BFF.",
                        rule_id="frontend-embedded-secret", revoke_required=revoke
                    ))

    def _scan_br_names(self, lines: list[str], filepath: str):
        data_ctx_re = re.compile(
            r"(?:INSERT INTO|VALUES|nome|name|cliente|customer|usuario|user|paciente)",
            re.IGNORECASE
        )
        name_like_re = re.compile(
            r"'([A-ZÁÉÍÓÚÃÕÂÊÎÔÛÇ][a-záéíóúãõâêîôûç]+)"
            r"(?:\s+[A-ZÁÉÍÓÚÃÕÂÊÎÔÛÇ][a-záéíóúãõâêîôûç]+)+'"
        )
        for i, line in enumerate(lines, 1):
            context = " ".join(lines[max(0, i - 2):min(len(lines), i + 2)])
            if not data_ctx_re.search(context):
                continue
            for m in name_like_re.finditer(line):
                first = m.group(1).lower()
                if first in BR_NAMES_COMMON:
                    self.issues.append(Issue(
                        file=filepath, line=i,
                        type="DADOS PESSOAIS — Nome próprio brasileiro (LGPD Art. 5, I)",
                        risk_level="high", confidence="medium",
                        impact="alto impacto — nome de pessoa real em dado estruturado",
                        decision="WARN",
                        message=f"Nome próprio detectado em linha de dados: '{m.group(0)}'. "
                                "Se for dado real de usuário, é PII identificável.",
                        suggestion="Substituir por nome fictício (ex: 'Usuário Teste'). "
                                   "Em produção, anonimizar ou pseudonimizar.",
                        rule_id="lgpd-br-name"
                    ))

    def _scan_env_vars(self, lines: list[str], filepath: str):
        basename = Path(filepath).name
        if basename in {".env", ".env.local", ".env.production", ".env.staging"}:
            self.issues.append(Issue(
                file=filepath, line=0,
                type="ARTEFATO INDEVIDO — Arquivo .env no artefato",
                risk_level="critical", confidence="high",
                impact="crítico — arquivo com todos os segredos incluído no build/deploy",
                decision="BLOCK",
                message=f"Arquivo {basename} detectado no artefato de deploy. "
                        "Arquivos .env nunca devem ser publicados.",
                suggestion="Adicionar ao .gitignore. Injetar variáveis via CI/CD secrets ou secret manager.",
                rule_id="artifact-dotenv"
            ))
