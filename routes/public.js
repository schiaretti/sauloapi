import express from 'express';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { messaging } from './firebase.js'; // Importa o módulo de Firebase

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

router.post('/cadastro-usuario', async (req, res) => {
  try {
    // 1. Validação dos campos obrigatórios
    const { email, nome, senha, cpf, telefone, nivel } = req.body;
    if (!email || !nome || !senha || !cpf || !telefone) {
      return res.status(400).json({
        message: "Todos os campos são obrigatórios!",
        camposFaltantes: {
          email: !email,
          nome: !nome,
          senha: !senha,
          cpf: !cpf,
          telefone: !telefone
        }
      });
    }

    // 2. Validação do formato do email (exemplo simples)
    if (!email.includes('@')) {
      return res.status(400).json({ message: "Formato de email inválido!" });
    }

    // 3. Criptografia da senha
    const salt = await bcrypt.genSalt(10);
    const hashSenha = await bcrypt.hash(senha, salt);

    // 4. Criação do usuário no banco de dados
    const usuarioDb = await prisma.usuario.create({
      data: {
        email,
        nome,
        senha: hashSenha,
        cpf,
        telefone,
        nivel: nivel || 'MOTORISTA',
      },
    });

    // 5. Geração do token JWT
    if (!JWT_SECRET) {
      console.error("Variável JWT_SECRET não está definida!");
      return res.status(500).json({ message: "Erro de configuração do servidor" });
    }

    const token = jwt.sign({ id: usuarioDb.id }, JWT_SECRET, { expiresIn: '1d' });

    // 6. Resposta de sucesso
    res.status(201).json({
      usuario: {
        id: usuarioDb.id,
        email: usuarioDb.email,
        nome: usuarioDb.nome,
        nivel: usuarioDb.nivel
      },
      token
    });

  } catch (error) {
    console.error("Erro no cadastro:", error);

    // Tratamento específico para erros do Prisma
    if (error.code === 'P2002') {
      const campo = error.meta?.target?.[0] || 'dados';
      return res.status(409).json({
        message: `Conflito: ${campo} já está em uso!`,
        detalhes: `O campo ${campo} informado já existe no sistema`
      });
    }

    // Erros de validação do JWT
    if (error instanceof jwt.JsonWebTokenError) {
      return res.status(500).json({
        message: "Erro na geração do token de autenticação",
        detalhes: error.message
      });
    }

    // Erros do bcrypt
    if (error.message.includes('bcrypt')) {
      return res.status(500).json({
        message: "Erro ao processar a senha",
        detalhes: "Falha na criptografia"
      });
    }

    // Erro genérico (com detalhes apenas em desenvolvimento)
    res.status(500).json({
      message: "Erro durante o cadastro",
      detalhes: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
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
        ano: parseInt(ano),
        capacidade: parseInt(capacidade),
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

router.delete('/veiculos/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;

    // 1. Verifica se o veículo existe e pertence ao motorista logado
    const veiculo = await prisma.veiculo.findUnique({
      where: { id }
    });

    if (!veiculo) {
      return res.status(404).json({ message: "Veículo não encontrado" });
    }

    if (veiculo.motoristaId !== req.user.id) {
      return res.status(403).json({ message: "Este veículo não pertence a você" });
    }

    // 2. Verifica se o veículo está vinculado a algum frete ativo
    const fretesVinculados = await prisma.frete.findFirst({
      where: {
        veiculoId: id,
        status: { in: ['RESERVADO', 'EM_TRANSPORTE'] }
      }
    });

    if (fretesVinculados) {
      return res.status(400).json({
        message: "Não é possível deletar um veículo vinculado a fretes ativos"
      });
    }

    // 3. Deleta o veículo
    await prisma.veiculo.delete({
      where: { id }
    });

    res.json({ message: "Veículo deletado com sucesso" });

  } catch (error) {
    console.error('Erro ao deletar veículo:', error);
    res.status(500).json({ message: "Erro ao deletar veículo" });
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

    // 1. Cria o frete no banco de dados
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
        valor: parseFloat(valor),
        whatsappContato,
        clienteNome,
        clienteTelefone,
        dataColeta: dataColeta ? new Date(dataColeta) : null,
        dataEntrega: dataEntrega ? new Date(dataEntrega) : null,
        status: 'DISPONIVEL'
      }
    });

    // 2. Busca motoristas com veículos compatíveis e token cadastrado
    const motoristas = await prisma.usuario.findMany({
      where: {
        nivel: 'MOTORISTA',
        veiculos: {
          some: {
            tipo: veiculoRequerido
          }
        },
        deviceToken: { not: null } // Só quem tem token cadastrado
      },
      select: {
        id: true,
        deviceToken: true,
        devicePlatform: true,
        nome: true
      }
    });

    // 3. Dispara alertas sonoros em paralelo
    await Promise.all(
      motoristas.map(async (motorista) => {
        try {
          // Configuração da notificação
          const payload = {
            token: motorista.deviceToken,
            notification: {
              title: `🚛 Novo Frete (${veiculoRequerido})`,
              body: `${origemCidade} → ${destinoCidade} - R$ ${valor}`,
            },
            android: {
              priority: "high",
              notification: {
                sound: "default",
                channelId: "alertas_fretes" // Canal específico para fretes
              }
            },
            apns: {
              payload: {
                aps: {
                  sound: "default",
                  badge: 1
                }
              }
            },
            data: {
              tipo: "NOVO_FRETE",
              freteId: frete.id,
              origem: origemCidade,
              destino: destinoCidade
            }
          };

          // Envia via Firebase
          await messaging.send(payload);

          // Registra o alerta no banco (opcional)
          await prisma.alertaSonoro.create({
            data: {
              userId: motorista.id,
              tipo: 'NOVO_FRETE',
              freteId: frete.id,
              titulo: `Novo frete ${veiculoRequerido}`,
              mensagem: `${origemCidade} → ${destinoCidade}`
            }
          });

          console.log(`✅ Alerta enviado para ${motorista.nome}`);

        } catch (error) {
          console.error(`❌ Falha no envio para ${motorista.nome}:`, error.message);
          
          // Remove token inválido do banco
          if (error.code === 'messaging/invalid-registration-token') {
            await prisma.usuario.update({
              where: { id: motorista.id },
              data: { deviceToken: null }
            });
          }
        }
      })
    );

    res.status(201).json({
      ...frete,
      alertasEnviados: motoristas.length
    });

  } catch (error) {
    console.error("Erro ao criar frete:", {
      message: error.message,
      stack: error.stack
    });

    // Tratamento específico para erros do Prisma
    if (error.code === 'P2002') {
      return res.status(400).json({ message: "Erro de duplicidade no frete" });
    }

    res.status(500).json({ 
      message: "Erro ao criar frete",
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
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

//rotas administrativas
router.put('/fretes/:id/finalizar', authenticate, async (req, res) => {
  try {
    const { id } = req.params;

    // Verifica se o usuário é admin
    if (req.user.nivel !== 'ADMIN') {
      return res.status(403).json({ message: "Apenas administradores podem finalizar fretes" });
    }

    // Verifica se o frete existe
    const frete = await prisma.frete.findUnique({
      where: { id }
    });

    if (!frete) {
      return res.status(404).json({ message: "Frete não encontrado" });
    }

    // Verifica se o frete está reservado
    if (frete.status !== 'RESERVADO') {
      return res.status(400).json({ message: "Apenas fretes reservados podem ser finalizados" });
    }

    // Atualiza o status do frete
    const updatedFrete = await prisma.frete.update({
      where: { id },
      data: {
        status: 'FINALIZADO',
        dataEntrega: new Date()
      },
      include: {
        motorista: true,
        veiculo: true
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
router.get('/admin/gerenciar-fretes', authenticate, isAdmin, async (req, res) => {
  try {
    console.log('Requisição recebida em /admin/gerenciar-fretes');
    const { status, page = 1, limit = 10 } = req.query;

    const where = {};
    if (status) where.status = status;

    const fretes = await prisma.frete.findMany({
      where,
      skip: (page - 1) * limit,
      take: parseInt(limit),
      orderBy: { createdAt: 'desc' },
      include: {
        motorista: {
          select: {
            nome: true,
            email: true,
            telefone: true
          }
        },
        veiculo: {
          select: {
            placa: true,
            modelo: true,
            tipo: true,
            capacidade: true,
            marca: true,
            ano: true
          }
        }
      }
    });

    const total = await prisma.frete.count({ where });

    res.json({
      data: fretes,
      pagination: {
        total,
        page: parseInt(page),
        totalPages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error('Erro detalhado:', {
      message: error.message,
      stack: error.stack
    });
    res.status(500).json({
      success: false,
      message: "Erro ao buscar fretes",
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
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

router.delete('/fretes/:id', authenticate, async (req, res) => {
  try {
    const { id } = req.params;

    // Verifica se o usuário é admin
    if (req.user.nivel !== 'ADMIN') {
      return res.status(403).json({ message: "Apenas administradores podem deletar fretes" });
    }

    // Verifica se o frete existe
    const frete = await prisma.frete.findUnique({
      where: { id }
    });

    if (!frete) {
      return res.status(404).json({ message: "Frete não encontrado" });
    }

    // Deleta o frete
    await prisma.frete.delete({
      where: { id }
    });

    res.json({ message: "Frete deletado com sucesso" });

  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Erro ao deletar frete" });
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

router.post('/auth/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    const decoded = jwt.verify(refreshToken, process.env.REFRESH_SECRET);

    const user = await User.findById(decoded.id);
    if (!user) return res.status(404).json({ message: 'Usuário não encontrado' });

    const newToken = jwt.sign(
      { id: user._id },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({ token: newToken });
  } catch (error) {
    res.status(401).json({ message: 'Refresh token inválido' });
  }
});

router.post("/usuario/registrar-dispositivo", authenticate, async (req, res) => {
  try {
    const { deviceToken, devicePlatform } = req.body;
    if (!deviceToken || !devicePlatform) {
      return res.status(400).json({ message: "deviceToken e devicePlatform são obrigatórios." });
    }
    await prisma.usuario.update({
      where: { id: req.user.id },
      data: {
        deviceToken: deviceToken,
        devicePlatform: devicePlatform,
      },
    });
    res.status(200).json({ message: "Token do dispositivo registrado com sucesso." });
  } catch (error) {
    console.error("Erro ao registrar token do dispositivo:",
      error);
    res.status(500).json({ message: "Erro interno do servidor." });
  }
});
// Rota de Relatórios Completa
router.get('/admin/relatorios', authenticate, isAdmin, async (req, res) => {
  try {
    // 1. Estatísticas Gerais
    const totalUsuarios = await prisma.usuario.count();
    const totalMotoristas = await prisma.usuario.count({
      where: { nivel: 'MOTORISTA' }
    });
    const totalAdmins = await prisma.usuario.count({
      where: { nivel: 'ADMIN' }
    });
    const totalVeiculos = await prisma.veiculo.count();

    // 2. Estatísticas de Fretes
    const fretesPorStatus = await prisma.frete.groupBy({
      by: ['status'],
      _count: { status: true },
      orderBy: { _count: { status: 'desc' } }
    });

    const fretesPorTipoVeiculo = await prisma.frete.groupBy({
      by: ['veiculoRequerido'],
      _count: { veiculoRequerido: true },
      orderBy: { _count: { veiculoRequerido: 'desc' } }
    });

    // 3. Fretes Recentes (últimos 7 dias)
    const seteDiasAtras = new Date();
    seteDiasAtras.setDate(seteDiasAtras.getDate() - 7);

    const fretesRecentes = await prisma.frete.count({
      where: {
        createdAt: { gte: seteDiasAtras }
      }
    });

    // 4. Valor Total em Fretes Finalizados
    const fretesFinalizados = await prisma.frete.aggregate({
      where: { status: 'FINALIZADO' },
      _sum: { valor: true },
      _count: { id: true }
    });

    // 5. Top Motoristas (com mais fretes finalizados)
    const topMotoristas = await prisma.frete.groupBy({
      by: ['motoristaId'],
      where: { status: 'FINALIZADO' },
      _count: { motoristaId: true },
      orderBy: { _count: { motoristaId: 'desc' } },
      take: 5
    });

    // 6. Veículos mais utilizados
    const veiculosMaisUtilizados = await prisma.frete.groupBy({
      by: ['veiculoId'],
      where: { status: 'FINALIZADO' },
      _count: { veiculoId: true },
      orderBy: { _count: { veiculoId: 'desc' } },
      take: 5
    });

    // 7. Fretes por período (últimos 12 meses)
    const agora = new Date();
    const dozeMesesAtras = new Date();
    dozeMesesAtras.setMonth(dozeMesesAtras.getMonth() - 12);

    const fretesPorMes = await prisma.$queryRaw`
      SELECT 
        DATE_TRUNC('month', "createdAt") as mes,
        COUNT(*) as total,
        SUM(CASE WHEN status = 'FINALIZADO' THEN 1 ELSE 0 END) as finalizados,
        SUM(CASE WHEN status = 'FINALIZADO' THEN valor ELSE 0 END) as valor_total
      FROM "Frete"
      WHERE "createdAt" >= ${dozeMesesAtras} AND "createdAt" <= ${agora}
      GROUP BY mes
      ORDER BY mes ASC
    `;

    // 8. Dispositivos registrados
    const dispositivosRegistrados = await prisma.usuario.count({
      where: {
        deviceToken: { not: null },
        devicePlatform: { not: null }
      }
    });

    // 9. Fretes por origem/destino mais comuns
    const origensMaisComuns = await prisma.frete.groupBy({
      by: ['origemCidade', 'origemEstado'],
      _count: { origemCidade: true },
      orderBy: { _count: { origemCidade: 'desc' } },
      take: 5
    });

    const destinosMaisComuns = await prisma.frete.groupBy({
      by: ['destinoCidade', 'destinoEstado'],
      _count: { destinoCidade: true },
      orderBy: { _count: { destinoCidade: 'desc' } },
      take: 5
    });

    // 10. Tempo médio de finalização de fretes
    const fretesComTempo = await prisma.frete.findMany({
      where: {
        status: 'FINALIZADO',
        dataColeta: { not: null },
        dataEntrega: { not: null }
      },
      select: {
        dataColeta: true,
        dataEntrega: true
      }
    });

    const tempos = fretesComTempo.map(f => {
      return (f.dataEntrega - f.dataColeta) / (1000 * 60 * 60); // horas
    });

    const tempoMedioHoras = tempos.length > 0 ?
      tempos.reduce((a, b) => a + b, 0) / tempos.length : 0;

    // Formatar os dados para resposta
    const relatorio = {
      estatisticasGerais: {
        totalUsuarios,
        totalMotoristas,
        totalAdmins,
        totalVeiculos,
        dispositivosRegistrados,
        fretesRecentes
      },
      fretes: {
        porStatus: fretesPorStatus,
        porTipoVeiculo: fretesPorTipoVeiculo,
        totalFinalizados: fretesFinalizados._count.id || 0,
        valorTotalFinalizados: fretesFinalizados._sum.valor || 0,
        tempoMedioFinalizacaoHoras: parseFloat(tempoMedioHoras.toFixed(2))
      },
      rankings: {
        topMotoristas: await Promise.all(topMotoristas.map(async m => {
          const usuario = await prisma.usuario.findUnique({
            where: { id: m.motoristaId },
            select: { nome: true, email: true }
          });
          return {
            ...usuario,
            fretesFinalizados: m._count.motoristaId
          };
        })),
        veiculosMaisUtilizados: await Promise.all(veiculosMaisUtilizados.map(async v => {
          const veiculo = await prisma.veiculo.findUnique({
            where: { id: v.veiculoId },
            select: { placa: true, modelo: true, marca: true }
          });
          return {
            ...veiculo,
            fretesFinalizados: v._count.veiculoId
          };
        })),
        origensMaisComuns,
        destinosMaisComuns
      },
      historico: {
        fretesPorMes: fretesPorMes.map(item => ({
          mes: item.mes.toISOString().split('T')[0].substring(0, 7),
          total: item.total,
          finalizados: item.finalizados,
          valorTotal: item.valor_total
        }))
      }
    };

    res.json({
      success: true,
      message: "Relatório gerado com sucesso",
      data: relatorio,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('Erro ao gerar relatório:', {
      message: error.message,
      stack: error.stack
    });
    res.status(500).json({
      success: false,
      message: "Erro ao gerar relatório",
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Rota para disparar alerta sonoro
router.post('/alertas/:userId/disparar', authenticate, isAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    const { tipo = 'ALERTA_SIMPLES' } = req.body;  // 👈 Captura o tipo

    // Verifica se o admin está tentando alertar a si mesmo
    if (req.user.id === userId) {
      return res.status(403).json({ message: "Não pode enviar alerta para si mesmo" });
    }

    // Busca o usuário e seu token
    const usuario = await prisma.usuario.findUnique({
      where: { id: userId },
      select: { deviceToken: true }
    });

    if (!usuario?.deviceToken) {
      return res.status(404).json({ message: "Usuário sem dispositivo registrado." });
    }

    // Registra o alerta (opcional)
    await prisma.alertaSonoro.create({
      data: { userId, tipo }
    });

    // Dispara o alerta sonoro via Firebase
    await messaging.send({
      token: usuario.deviceToken,
      priority: "high",  // 👈 Prioridade máxima
      notification: {
        title: "⚠️ Novo Alerta",
        body: "Você tem um novo frete disponível!",
      },
      android: {
        priority: "high",
        notification: {
          sound: "default",
          channelId: "alerts"  // Certifique-se de criar este canal no app
        }
      },
      apns: {
        payload: {
          aps: {
            sound: "default",
          },
        },
      },
      data: {
        tipo: "ALERTA_SONORO",
        click_action: "FLUTTER_NOTIFICATION_CLICK",  // Para Flutter
      },
    });

    res.json({ success: true, message: "Alerta sonoro enviado!" });

  } catch (error) {
    console.error("Erro ao enviar alerta:", error);

    // Trata erros específicos do Firebase
    if (error.code === 'messaging/invalid-registration-token') {
      await prisma.usuario.update({
        where: { id: userId },
        data: { deviceToken: null }
      });
      return res.status(400).json({ message: "Token inválido. Dispositivo removido." });
    }

    res.status(500).json({ message: "Erro ao enviar alerta." });
  }
});

router.get('/alertas/meus-alertas', authenticate, async (req, res) => {
  const { limit = 10, cursor } = req.query;
  
  const alertas = await prisma.alertaSonoro.findMany({
    where: { userId: req.user.id },
    orderBy: { createdAt: 'desc' },
    take: parseInt(limit),
    cursor: cursor ? { id: cursor } : undefined,
    skip: cursor ? 1 : 0
  });

  res.json({
    data: alertas,
    nextCursor: alertas.length > 0 ? alertas[alertas.length-1].id : null
  });
});

export default router;