// Cenário "limpo" — deve passar no Deploy Guard
// Backend Node.js correto usando variáveis de ambiente

import express from 'express';
import { createClient } from '@supabase/supabase-js';
import Stripe from 'stripe';

const app = express();

// Correto: usando process.env
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

// CORS configurado com origem específica
app.use(cors({
  origin: process.env.ALLOWED_ORIGIN || 'https://app.company.com',
  credentials: true,
}));

// Rota de pagamento — sem dados sensíveis hardcoded
app.post('/api/checkout', async (req, res) => {
  const { amount, currency } = req.body;

  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [{ price_data: { currency, unit_amount: amount }, quantity: 1 }],
      mode: 'payment',
      success_url: `${process.env.BASE_URL}/success`,
      cancel_url: `${process.env.BASE_URL}/cancel`,
    });

    res.json({ sessionId: session.id });
  } catch (err) {
    // Log sem expor detalhes internos
    console.error('Checkout error:', err.message);
    res.status(500).json({ error: 'Payment failed' });
  }
});

// Health check simples
app.get('/health', (req, res) => {
  res.json({ status: 'ok', version: process.env.APP_VERSION || '1.0.0' });
});

app.listen(process.env.PORT || 3000);
