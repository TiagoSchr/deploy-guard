-- Dump de produção incluído acidentalmente no repositório
-- Este arquivo NÃO deveria existir no deploy

CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  name VARCHAR(255),
  email VARCHAR(255) UNIQUE,
  cpf VARCHAR(14),
  phone VARCHAR(20),
  password_hash VARCHAR(255),
  created_at TIMESTAMP DEFAULT NOW()
);

INSERT INTO users (name, email, cpf, phone, password_hash) VALUES
('João da Silva', 'joao@empresa.com', '123.456.789-00', '+55 11 99999-1111', '$2b$10$hashedpassword1'),
('Maria Santos', 'maria@empresa.com', '987.654.321-00', '+55 21 88888-2222', '$2b$10$hashedpassword2'),
('Carlos Oliveira', 'carlos@empresa.com', '456.789.123-00', '+55 31 77777-3333', '$2b$10$hashedpassword3'),
('Ana Costa', 'ana.costa@empresa.com', '321.654.987-00', '+55 41 66666-4444', '$2b$10$hashedpassword4');

CREATE TABLE orders (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id),
  total DECIMAL(10,2),
  card_last_four VARCHAR(4),
  card_brand VARCHAR(20),
  status VARCHAR(50)
);

INSERT INTO orders (user_id, total, card_last_four, card_brand, status) VALUES
(1, 1250.00, '4242', 'Visa', 'completed'),
(2, 890.50, '5555', 'Mastercard', 'completed'),
(3, 3200.00, '1234', 'Amex', 'pending');

CREATE TABLE api_keys (
  id SERIAL PRIMARY KEY,
  service VARCHAR(100),
  key_value TEXT,
  created_at TIMESTAMP DEFAULT NOW()
);

INSERT INTO api_keys (service, key_value) VALUES
('stripe', 'supersecretstripekey2024production'),
('sendgrid', 'SG.aBcDeFgHiJkLmNoPqRsTuV.WxYzAbCdEfGhIjKlMnOpQrStUvWxYz'),
('openai', 'sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz1234567890');
