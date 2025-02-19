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

router.post('/login', async (req, res) => {

    try {
        const usuarioInfo = req.body

        //busca usuario no banco
        const usuario = await prisma.usuario.findUnique({ where: { email: usuarioInfo.email } })

        //verifica se o usuario existe
        if (!usuario) {
            return res.status(404).json({ message: "Usuário não encontrado!" })
        }
        //compara a senha no banco
        const isMatch = await bcrypt.compare(usuarioInfo.password, usuario.password)
        if (!isMatch) {
            return res.status(400).json({ message: "Senha inválida!" })
        }

        //gerar jwt
        const token = jwt.sign({id: user.id}, JWT_SECRET,{expiresIn:'7d'})


        res.status(200).json(token)

    } catch (error) {
        res.status(500).json({ message: "Erro no servidor!" })
    }
})


export default router