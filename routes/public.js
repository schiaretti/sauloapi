import express from 'express';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

const prisma = new PrismaClient();
const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET;

// Middleware de autenticação
const authenticate = async (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  
  if (!token) {
    return res.status(401).json({ message: 'Acesso não autorizado' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await prisma.usuario.findUnique({ where: { id: decoded.id } });
    
    if (!user) {
      throw new Error();
    }

    req.user = user;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Token inválido' });
  }
};

// Middleware para verificar se é admin
const isAdmin = (req, res, next) => {
  if (req.user.nivel === 'ADMIN') {
    return next();
  }
  res.status(403).json({ message: 'Acesso negado - Requer privilégios de admin' });
};

// Rotas de Autenticação
router.post('/cadastro-usuario', async (req, res) => {
  try {
    const { email, nome, senha, cpf, telefone, nivel } = req.body;
    const salt = await bcrypt.genSalt(10);
    const hashSenha = await bcrypt.hash(senha, salt);

    const usuarioDb = await prisma.usuario.create({
      data: {
        email,
        nome,
        senha: hashSenha,
        cpf,
        telefone,
        nivel: nivel || 'MOTORISTA', // Default para motorista
      },
    });

    // Gerar token JWT
    const token = jwt.sign({ id: usuarioDb.id }, JWT_SECRET, { expiresIn: '1d' });

    res.status(201).json({ usuario: usuarioDb, token });
  } catch (error) {
    if (error.code === 'P2002') {
      return res.status(400).json({ message: "Email ou CPF já cadastrado!" });
    }
    res.status(500).json({ message: "Erro no servidor tente novamente!" });
  }
});

router.post('/login', async (req, res) => {
  try {
    const { email, senha } = req.body;

    const usuario = await prisma.usuario.findUnique({
      where: { email }
    });

    if (!usuario) {
      return res.status(404).json({ message: "Usuário não encontrado!" });
    }

    const isMatch = await bcrypt.compare(senha, usuario.senha);
    if (!isMatch) {
      return res.status(400).json({ message: "Credenciais inválidas!" });
    }

    const token = jwt.sign({ id: usuario.id }, JWT_SECRET, { expiresIn: '7d' });

    res.status(200).json({ 
      message: "Login realizado com sucesso", 
      usuario: {
        id: usuario.id,
        nome: usuario.nome,
        email: usuario.email,
        nivel: usuario.nivel
      },
      token 
    });

  } catch (error) {
    console.error("Erro ao tentar logar:", error);
    res.status(500).json({ message: "Erro no servidor!" });
  }
});

// Rotas de Veículos (requer autenticação)
router.post('/veiculos', authenticate, async (req, res) => {
  try {
    const { tipo, placa, marca, modelo, ano, capacidade } = req.body;

    const veiculo = await prisma.veiculo.create({
      data: {
        tipo,
        placa,
        marca,
        modelo,
        ano,
        capacidade,
        motoristaId: req.user.id
      }
    });

    res.status(201).json(veiculo);
  } catch (error) {
    if (error.code === 'P2002') {
      return res.status(400).json({ message: "Placa já cadastrada!" });
    }
    res.status(500).json({ message: "Erro ao cadastrar veículo" });
  }
});

router.get('/veiculos', authenticate, async (req, res) => {
  try {
    const veiculos = await prisma.veiculo.findMany({
      where: { motoristaId: req.user.id }
    });

    res.json(veiculos);
  } catch (error) {
    res.status(500).json({ message: "Erro ao buscar veículos" });
  }
});

// Rotas de Fretes
router.get('/fretes/disponiveis', authenticate, async (req, res) => {
  try {
    const { tipoVeiculo, origem, destino } = req.query;

    const where = {
      status: 'DISPONIVEL'
    };

    if (tipoVeiculo) {
      where.veiculoRequerido = tipoVeiculo;
    }

    if (origem) {
      where.OR = [
        { origemCidade: { contains: origem } },
        { origemEstado: { contains: origem } }
      ];
    }

    if (destino) {
      where.OR = [
        ...(where.OR || []),
        { destinoCidade: { contains: destino } },
        { destinoEstado: { contains: destino } }
      ];
    }

    const fretes = await prisma.frete.findMany({
      where,
      orderBy: { createdAt: 'desc' }
    });

    res.json(fretes);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Erro ao buscar fretes disponíveis" });
  }
});

router.post('/fretes', authenticate, isAdmin, async (req, res) => {
  try {
    const {
      origemCidade, origemEstado, origemEndereco,
      destinoCidade, destinoEstado, destinoEndereco,
      veiculoRequerido, cargaDescricao, valor,
      whatsappContato, clienteNome, clienteTelefone,
      dataColeta, dataEntrega
    } = req.body;

    const frete = await prisma.frete.create({
      data: {
        origemCidade,
        origemEstado,
        origemEndereco,
        destinoCidade,
        destinoEstado,
        destinoEndereco,
        veiculoRequerido,
        cargaDescricao,
        valor,
        whatsappContato,
        clienteNome,
        clienteTelefone,
        dataColeta: dataColeta ? new Date(dataColeta) : null,
        dataEntrega: dataEntrega ? new Date(dataEntrega) : null,
        status: 'DISPONIVEL'
      }
    });

    res.status(201).json(frete);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Erro ao criar frete" });
  }
});

router.post('/fretes/:id/interesse', authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    
    // Verifica se o frete existe e está disponível
    const frete = await prisma.frete.findUnique({
      where: { id }
    });

    if (!frete || frete.status !== 'DISPONIVEL') {
      return res.status(400).json({ message: "Frete não disponível" });
    }

    // Verifica se o motorista tem veículo compatível
    const veiculos = await prisma.veiculo.findMany({
      where: { 
        motoristaId: req.user.id,
        tipo: frete.veiculoRequerido 
      }
    });

    if (veiculos.length === 0) {
      return res.status(400).json({ 
        message: "Você não possui veículo compatível com este frete" 
      });
    }

    // Atualiza o frete com o motorista e veículo
    const updatedFrete = await prisma.frete.update({
      where: { id },
      data: {
        status: 'RESERVADO',
        motoristaId: req.user.id,
        veiculoId: veiculos[0].id
      }
    });

    res.json({
      message: "Frete reservado com sucesso",
      frete: updatedFrete,
      whatsapp: frete.whatsappContato
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Erro ao registrar interesse no frete" });
  }
});

router.put('/fretes/:id/finalizar', authenticate, async (req, res) => {
  try {
    const { id } = req.params;

    // Verifica se o frete existe e pertence ao motorista
    const frete = await prisma.frete.findUnique({
      where: { id }
    });

    if (!frete || frete.motoristaId !== req.user.id) {
      return res.status(404).json({ message: "Frete não encontrado ou não pertence a você" });
    }

    // Atualiza o status do frete
    const updatedFrete = await prisma.frete.update({
      where: { id },
      data: {
        status: 'FINALIZADO',
        dataEntrega: new Date()
      }
    });

    res.json({
      message: "Frete finalizado com sucesso",
      frete: updatedFrete
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Erro ao finalizar frete" });
  }
});

// Rotas administrativas
router.get('/admin/fretes', authenticate, isAdmin, async (req, res) => {
  try {
    const fretes = await prisma.frete.findMany({
      orderBy: { createdAt: 'desc' },
      include: {
        motorista: { select: { nome: true, email: true } },
        veiculo: { select: { placa: true, modelo: true } }
      }
    });

    res.json(fretes);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Erro ao buscar fretes" });
  }
});

router.get('/admin/usuarios', authenticate, isAdmin, async (req, res) => {
  try {
    const usuarios = await prisma.usuario.findMany({
      select: {
        id: true,
        nome: true,
        email: true,
        cpf: true,
        telefone: true,
        nivel: true,
        createdAt: true
      },
      orderBy: { nome: 'asc' }
    });

    res.json(usuarios);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Erro ao buscar usuários" });
  }
});

// Adicione esta rota no seu arquivo de rotas (routes.js)
router.get('/admin/estatisticas', authenticate, isAdmin, async (req, res) => {
  try {
    const totalFretes = await prisma.frete.count()
    const fretesDisponiveis = await prisma.frete.count({
      where: { status: 'DISPONIVEL' }
    })
    const fretesReservados = await prisma.frete.count({
      where: { status: 'RESERVADO' }
    })
    const fretesFinalizados = await prisma.frete.count({
      where: { status: 'FINALIZADO' }
    })

    res.json({
      totalFretes,
      fretesDisponiveis,
      fretesReservados,
      fretesFinalizados,
      // Adicione mais estatísticas conforme necessário
      percentualDisponivel: (fretesDisponiveis / totalFretes * 100).toFixed(1),
      percentualFinalizado: (fretesFinalizados / totalFretes * 100).toFixed(1)
    })
  } catch (error) {
    console.error('Erro ao buscar estatísticas:', error)
    res.status(500).json({ message: "Erro ao buscar estatísticas" })
  }
})

export default router;