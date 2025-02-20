import express from 'express'
import { PrismaClient } from '@prisma/client'
import bcrypt from 'bcrypt'

const prisma = new PrismaClient()
const router = express.Router()




router.post('/cadastro-usuario', async (req, res) => {

    try {
        const usuario = req.body
        const salt = await bcrypt.genSalt(10)
        const hashSenha = await bcrypt.hash(usuario.senha, salt)


        const usuarioDb = await prisma.usuario.create({
            data: {
                email: usuario.email,
                nome: usuario.nome,
                senha: hashSenha,
            },
        })

        res.status(201).json(usuarioDb)
    } catch (error) {
        res.status(500).json({ message: "Erro no servidor tente novamente!" })
    }

})

router.get('/listar-usuarios', async (req, res) => {
    try {
        const usuario = await prisma.usuario.findMany(); // Mudando o nome da variável para um termo mais adequado

        if (usuario.length === 0) {
            return res.status(404).json({ message: "Nenhum usuário encontrado!" });
        }

        res.status(200).json({ message: "Usuários listados com sucesso!", usuario });
    } catch (error) {
        console.error("Erro ao buscar usuários:", error);
        res.status(500).json({ message: "Erro no servidor!", error: error.message });
    }
});

router.post('/login', async (req, res) => {
    try {
        const usuarioInfo = req.body;

        // Busca usuário no banco
        const usuario = await prisma.usuario.findUnique({
            where: { email: usuarioInfo.email }
        });

        // Verifica se o usuário existe
        if (!usuario) {
            return res.status(404).json({ message: "Usuário não encontrado!" });
        }

        // Compara a senha no banco
        const isMatch = await bcrypt.compare(usuarioInfo.senha, usuario.senha);
        if (!isMatch) {
            return res.status(400).json({ message: "Senha inválida!" });
        }

        res.status(200).json({ message: "Login realizado com sucesso", usuario });

    } catch (error) {
        console.error("Erro ao tentar logar:", error);
        res.status(500).json({ message: "Erro no servidor!" });
    }
});


router.post('/cadastro-clientes', async (req, res) => {
    try {
        const { email, nome, cnpj, celular, contato } = req.body; // Pegando os dados do corpo da requisição

        const cliente = await prisma.cliente.create({
            data: {
                email,
                nome,
                cnpj,
                celular,
                contato,
            },
        });

       
        res.status(201).json(cliente);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Erro no servidor, tente novamente!" });
    }
});


router.post('/cadastro-fretes', async (req, res) => {
    try {
        const { usuario, cliente, cidorigem, ciddestino, freteemp, fretemot, produto, veiculo } = req.body; // Pegando os dados do corpo da requisição

        const logistica = await prisma.logistica.create({
            data: {
                usuario,
                cliente,
                cidorigem,
                ciddestino,
                freteemp,
                fretemot,
                produto,
                veiculo,
            },
        });

        res.status(201).json(logistica);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Erro no servidor, tente novamente!" });
    }
});


router.get('/listar-fretes', async (req, res) => {
    try {
        const fretes = await prisma.logistica.findMany(); // Mudando o nome da variável para um termo mais adequado

        if (fretes.length === 0) {
            return res.status(404).json({ message: "Nenhum frete encontrado!" });
        }

        res.status(200).json({ message: "Fretes listados com sucesso!", fretes });
    } catch (error) {
        console.error("Erro ao buscar fretes:", error);
        res.status(500).json({ message: "Erro no servidor!", error: error.message });
    }
});

router.delete('/logistica/:id', async (req,res) =>{
    await prisma.logistica.delete({
        where: {
            id: req.params.id
        }
    })
    res.status(200).json({message: "Frete deletado com sucesso!"})
})

router.delete('/usuario/:id', async (req,res) =>{
    await prisma.usuario.delete({
        where: {
            id: req.params.id
        }
    })
    res.status(200).json({message: "Usuário deletado com sucesso!"})
})
export default router