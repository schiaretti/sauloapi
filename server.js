import express from "express";
import publicRoutes from './routes/public.js';
import cors from 'cors';

const app = express();

// Usar CORS e JSON
app.use(cors());

app.use(express.json());

// Definir as rotas
app.use('/', publicRoutes);



app.listen(3000, () => {
  console.log('Servidor rodando');
});
