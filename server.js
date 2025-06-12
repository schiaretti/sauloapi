import express from 'express';
import routes from './routes/public.js';
import cors from 'cors';

const app = express();

// Configuração robusta do CORS
const corsOptions = {
  origin: ['http://localhost:5173', 'https://fretes-indol.vercel.app/'], // Adicione todos os domínios permitidos
  methods: 'GET,POST,PUT,DELETE',
  allowedHeaders: 'Content-Type,Authorization',
  credentials: true,
  optionsSuccessStatus: 204
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions)); // Habilitar preflight para todas rotas
app.use(express.json());
app.use('/api', routes);

// Rota health check para o Railway
app.get('/health', (req, res) => res.status(200).send('OK'));

const PORT = process.env.PORT || 8080;
app.listen(PORT, '0.0.0.0', () => { // Ouvir em todos os interfaces
  console.log(`Servidor rodando na porta ${PORT}`);
});