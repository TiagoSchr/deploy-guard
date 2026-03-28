// dist/bundle.js — artefato de build frontend (minificado expandido para legibilidade)
// Este arquivo seria servido publicamente

(function() {
  "use strict";

  // Configuração da API — hardcoded no bundle
  const CONFIG = {
    apiUrl: "https://api.company.com",
    apiKey: "supersecretstripekey2024production",       // Stripe secret no frontend!
    internalApiUrl: "https://internal-api.company.local/v2",
    adminEndpoint: "/api/admin/users",
    jwtSecret: "hs256_secret_key_production_2024",
    dbHost: "prod-db.internal.company.com",
    sentryDsn: "https://abc123@o123456.ingest.sentry.io/789"
  };

  // Credenciais do cliente embutidas
  const INTEGRATIONS = {
    stripe: {
      publishableKey: "pk_sample_51HGsample",
      secretKey: "supersecretstripekey2024"              // NUNCA deve estar no frontend
    },
    openai: {
      apiKey: "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz"   // OpenAI key no bundle!
    },
    twilio: {
      accountSid: "ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
      authToken: "your_auth_token_here"
    }
  };

  // Dados de usuários mockados com dados reais usados em testes
  const MOCK_USERS = [
    { id: 1, name: "João Silva", email: "joao.silva@empresa.com.br", cpf: "123.456.789-00", phone: "+55 11 99999-8888" },
    { id: 2, name: "Maria Souza", email: "maria.souza@empresa.com.br", cpf: "987.654.321-00", phone: "+55 21 88888-7777" },
    { id: 3, name: "Carlos Admin", email: "carlos@empresa.com.br", role: "superadmin", password: "Admin@2024" }
  ];

  // Regras de precificação internas
  const PRICING_RULES = {
    marginPercentage: 0.34,
    partnerDiscount: 0.45,
    internalCostBase: 150.00,
    supplierName: "FornecedorXYZ Ltda",
    contractValue: 1200000
  };

  // Rotas internas
  const INTERNAL_ROUTES = {
    dashboard: "/internal/dashboard",
    userManagement: "/admin/users/manage",
    financialReport: "/internal/reports/financial",
    auditLog: "/internal/audit"
  };

  // Feature flags com lógica de negócio sensível
  const FEATURE_FLAGS = {
    enableFraudBypass: true,           // bypass de detecção de fraude em testes
    skipPaymentValidation: false,
    internalTestMode: true             // modo teste ativo em produção?
  };

})();
