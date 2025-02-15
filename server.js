import express from "express";
import publicRoutes from './routes/public.js';
import cors from 'cors';

const app = express();

// Usar CORS e JSON
app.use(cors());
app.use(express.json());

// Definir as rotas
app.use('/', publicRoutes);

// Iniciar o servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
