import express from "express";
import publicRoutes from './routes/public.js';
import cors from 'cors';

const app = express();

// Usar CORS e JSON
app.use(cors({
  origin: ['http://localhost:5173', 'https://fretes-rho.vercel.app/'],
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

// Definir as rotas
app.use('/', publicRoutes);



app.listen(3000, () => {
  console.log('Servidor rodando');
});
