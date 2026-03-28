"""Detection patterns for secrets, insecure configs, artifacts, and frontend exposure."""

# Padrões de secrets conhecidos
SECRET_PATTERNS = [
    # AWS
    (r'\bAKIA[0-9A-Z]{16}\b', "AWS Access Key ID", "critical", True),
    (r'(?<![A-Za-z0-9/+@])(?:[A-Za-z0-9/+]{40})(?![A-Za-z0-9/+@=.])\b',
     "Possível AWS Secret Key (40 chars base64)", "high", False),
    # Stripe
    (r'\bsk_live_[0-9a-zA-Z]{24,}\b', "Stripe Secret Key (live)", "critical", True),
    (r'\brk_live_[0-9a-zA-Z]{24,}\b', "Stripe Restricted Key (live)", "critical", True),
    (r'\bsk_test_[0-9a-zA-Z]{24,}\b', "Stripe Secret Key (test) — remover do deploy", "medium", False),
    # OpenAI
    (r'\bsk-proj-[A-Za-z0-9_-]{48,}\b', "OpenAI Project API Key", "critical", True),
    (r'\bsk-[A-Za-z0-9]{48}\b', "OpenAI API Key (legacy)", "critical", True),
    # SendGrid
    (r'\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b', "SendGrid API Key", "critical", True),
    # GitHub
    (r'\bghp_[A-Za-z0-9]{36}\b', "GitHub Personal Access Token", "critical", True),
    (r'\bgho_[A-Za-z0-9]{36}\b', "GitHub OAuth Token", "critical", True),
    (r'\bghs_[A-Za-z0-9]{36}\b', "GitHub App Secret", "critical", True),
    # Slack
    (r'hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+',
     "Slack Webhook URL", "high", True),
    (r'\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,}\b', "Slack Token", "critical", True),
    # JWT
    (r'\beyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b', "JSON Web Token (JWT)", "medium", False),
    # Private keys
    (r'-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----', "Chave Privada (PEM)", "critical", True),
    # Connection strings com senha
    (r'(?:postgres|postgresql|mysql|mongodb|redis)://[^:]+:[^@\s"\']+@[^\s"\']+',
     "Connection String com credencial", "critical", True),
    # Generic secrets em variáveis
    (r'(?:password|passwd|secret|api_key|api-key|apikey|token|auth_token)\s*[=:]\s*["\'](?!(?:"|\'|\s*$|\$\{|\$\())[^"\']{6,}["\']',
     "Possível credencial hardcoded", "high", False),
]

# Padrões de configuração insegura
INSECURE_CONFIG_PATTERNS = [
    (r'\bDEBUG\s*[=:]\s*(?:true|1|yes|on)\b', "DEBUG ativo", "high",
     "DEBUG=true em produção expõe stack traces e informações internas."),
    (r'Access-Control-Allow-Origin["\']?\s*[=:,]\s*["\']?\*["\']?', "CORS totalmente aberto (*)", "high",
     "CORS com * permite qualquer origem. Restringir para domínios específicos."),
    (r'"Action"\s*:\s*"\*"', "IAM Action wildcard (*)", "critical",
     "Permissão irrestrita em IAM. Definir apenas as ações necessárias."),
    (r'"Resource"\s*:\s*"\*"', "IAM Resource wildcard (*)", "high",
     "Recurso IAM irrestrito. Especificar ARNs exatos."),
    (r'publicly_accessible\s*=\s*true', "RDS publicly_accessible=true", "critical",
     "Banco de dados exposto à internet. Definir publicly_accessible=false."),
    (r'acl\s*=\s*["\']public-read["\']', "S3 public-read ACL", "critical",
     "Bucket S3 público. Usar private e aws_s3_bucket_public_access_block."),
    (r'ports:\s*\n\s*-\s*["\']?6379:6379', "Redis exposto no host", "high",
     "Porta Redis exposta. Serviços internos não devem mapear portas para o host."),
    (r'ports:\s*\n\s*-\s*["\']?5432:5432', "PostgreSQL exposto no host", "critical",
     "Porta PostgreSQL exposta externamente. Remover mapeamento de porta."),
    (r'\benv\b.*\|\s*grep\b', "Variáveis de ambiente printadas em log", "high",
     "Executar 'env | grep' em CI imprime segredos nos logs. Remover."),
    (r'skip_final_snapshot\s*=\s*true', "RDS skip_final_snapshot=true", "medium",
     "Sem snapshot antes de destruir o banco. Risco de perda de dados em produção."),
]

# Artefatos indevidos
ARTIFACT_EXTENSIONS_HIGH = {".pem", ".key", ".p12", ".pfx", ".jks"}
ARTIFACT_EXTENSIONS_CRITICAL = {".sql", ".dump", ".bak"}
ARTIFACT_EXTENSIONS_WARN = {".csv", ".tsv", ".xlsx", ".xls", ".ods", ".log"}

# NEXT_PUBLIC / VITE_ / PUBLIC_ com conteúdo sensível
FRONTEND_ENV_PATTERNS = [
    (r'NEXT_PUBLIC_\w*(?:SECRET|KEY|TOKEN|PASSWORD|PASS|JWT|AUTH|ADMIN|INTERNAL|PRIVATE|DATABASE|DB)\w*\s*=\s*.+',
     "Variável NEXT_PUBLIC_ com nome sensível", "critical"),
    (r'VITE_\w*(?:SECRET|KEY|TOKEN|PASSWORD|PASS|JWT|AUTH|ADMIN|INTERNAL|PRIVATE|DATABASE|DB)\w*\s*=\s*.+',
     "Variável VITE_ com nome sensível", "critical"),
    (r'(?:NEXT_PUBLIC_|VITE_|PUBLIC_)\w+\s*=\s*(?:sk_live_|sk-proj-|SG\.|AKIA|ghp_)',
     "Variável de frontend com valor de secret real", "critical"),
]
