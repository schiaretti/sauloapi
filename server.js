import express from 'express';
import routes from './routes/public.js';
import cors from 'cors';

// Configuração de timeout
process.env.HTTP_SERVER_TIMEOUT = '600000';

const app = express();

// CORS Config
const corsOptions = {
  origin: ['http://localhost:5173'],
  methods: 'GET,POST,PUT,DELETE',
  allowedHeaders: 'Content-Type,Authorization',
  credentials: true,
  optionsSuccessStatus: 204
};



app.use(cors(corsOptions));
app.options('*', cors(corsOptions));
app.use(express.json());
app.use('/api', routes);

// Health Check
app.get('/health', (req, res) => res.status(200).send('OK'));

// Error Handling
app.use((req, res) => {
  res.status(404).json({ error: 'Rota não encontrada' });
});

app.use((err, req, res, next) => {
  console.error('🔥 Erro:', err.stack);
  res.status(500).json({ error: 'Erro interno do servidor' });
});

// Middleware para rotas não encontradas (404)
app.use((req, res, next) => {
  const error = new Error(`Rota não encontrada: ${req.originalUrl}`);
  error.statusCode = 404;
  next(error);
});

// Middleware global de erros
app.use((error, req, res, next) => {
  const statusCode = error.statusCode || 500;
  const message = error.message || 'Erro interno do servidor';

  // Log completo do erro (aparecerá no Railway)
  console.error(`\n🚨 ERRO ${statusCode}:`, {
    message: message,
    path: req.originalUrl,
    stack: process.env.NODE_ENV === 'development' ? error.stack : undefined,
    timestamp: new Date().toISOString()
  });

  // Resposta ao cliente
  res.status(statusCode).json({
    success: false,
    status: statusCode,
    message: message,
    ...(process.env.NODE_ENV === 'development' && { stack: error.stack })
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Servidor iniciado`, {
    port: PORT,
    node_env: process.env.NODE_ENV,
    railway_env: process.env.RAILWAY_ENVIRONMENT
  });
});