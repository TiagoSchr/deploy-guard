"""PDF scanning support (requires pdfplumber)."""

from .models import Issue
from .scanner import DeployGuard


def _try_import_pdf():
    try:
        import pdfplumber
        return pdfplumber
    except ImportError:
        return None


def scan_pdf(filepath: str, guard: "DeployGuard") -> list[Issue]:
    pdfplumber = _try_import_pdf()
    if pdfplumber is None:
        return [Issue(
            file=filepath, line=0,
            type="AVISO — PDF não escaneado",
            risk_level="medium", confidence="high",
            impact="médio impacto — PDF não analisado por falta de dependência",
            decision="REQUIRE_OVERRIDE",
            message="PDF detectado mas pdfplumber não está instalado. Conteúdo não escaneado.",
            suggestion="Instalar: pip install pdfplumber — e re-escanear.",
            rule_id="pdf-no-lib"
        )]

    issues = []
    try:
        with pdfplumber.open(filepath) as pdf:
            all_text = []
            for page_num, page in enumerate(pdf.pages, 1):
                text = page.extract_text()
                if text:
                    all_text.append((page_num, text))

            if not all_text:
                return [Issue(
                    file=filepath, line=0,
                    type="AVISO — PDF de imagem não escaneado",
                    risk_level="low", confidence="high",
                    impact="baixo impacto — PDF sem camada de texto detectável",
                    decision="WARN",
                    message="PDF sem camada de texto (provavelmente escaneado/imagem). "
                            "Conteúdo não pode ser analisado sem OCR.",
                    suggestion="Verificar manualmente se o PDF contém dados sensíveis antes de publicar.",
                    rule_id="pdf-image-only"
                )]

            for page_num, text in all_text:
                lines = text.splitlines()
                label = f"{filepath} [pág. {page_num}]"
                sub_guard = DeployGuard(target=guard.target, strict_lgpd=guard.strict_lgpd)
                sub_guard._scan_lgpd(lines, label, ".txt", text)
                sub_guard._scan_secrets(lines, label)
                issues.extend(sub_guard.issues)

    except Exception as e:
        issues.append(Issue(
            file=filepath, line=0,
            type="ERRO — Falha ao ler PDF",
            risk_level="low", confidence="high",
            impact="baixo impacto",
            decision="WARN",
            message=f"Não foi possível ler o PDF: {e}",
            suggestion="Verificar manualmente.",
            rule_id="pdf-error"
        ))
    return issues
