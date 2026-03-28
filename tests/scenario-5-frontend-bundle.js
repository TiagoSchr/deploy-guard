// dist/bundle.js — artefato de build frontend (minificado expandido para legibilidade)
// Este arquivo seria servido publicamente

(function() {
  "use strict";

  // Configuração da API
  const CONFIG = {
    apiUrl: "https://api.company.com",
    apiKey: process.env.API_KEY,
    sentryDsn: "https://o123456.ingest.sentry.io/789"
  };

  // Integração de pagamento
  const PAYMENT = {
    endpoint: "/api/checkout",
    currency: "BRL",
    maxRetries: 3
  };

  // Dados de usuário mockado com dado real — ERRO!
  const MOCK_USER = {
    id: 1,
    name: "João Silva",
    email: "user@example.com",
    cpf: "987.654.321-00",
    role: "cliente"
  };

  // Configuração com DEBUG ativo — ERRO!
  const APP_CONFIG = {
    debug: true,
    DEBUG: true,
    logLevel: "verbose",
    environment: "production"
  };

  // Credencial hardcoded — ERRO!
  const DB_CONFIG = {
    host: "prod-db.internal.company.com",
    password: "SuperSecretProd2024!"
  };

  // Rotas públicas (OK)
  const ROUTES = {
    home: "/",
    products: "/products",
    cart: "/cart",
    checkout: "/checkout"
  };

  console.log("App initialized");
})();
    internalTestMode: true             // modo teste ativo em produção?
  };

})();
