import express from 'express'
import { PrismaClient } from '@prisma/client'
import bcrypt from 'bcrypt'

const prisma = new PrismaClient()
const router = express.Router()

router.get('/', async (req, res) => {
    try {
        const usuarios = await prisma.usuario.findMany();
        res.status(200).json({ message: "Usuários listados com sucesso!", usuarios });
    } catch (error) {
        console.error("Erro ao buscar usuários:", error);
        res.status(500).json({ message: "Erro no servidor!", error: error.message });
    }
});


router.post('/cadastro', async (req, res) => {

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


export default router