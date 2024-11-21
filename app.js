require('dotenv').config()  // Carrega as variáveis de ambiente
const express = require('express')
const bcrypt = require('bcrypt')
const mongoose = require('mongoose')
const jwt = require('jsonwebtoken')

const app = express()

app.use(express.json())

const User = require('./models/User')

app.get('/', (req, res) => {
    res.status(200).json({ msg: 'Hola, Juan' })
})

// Rota para obter os detalhes do usuário, com verificação de token
app.get('/user/:id', checkToken, async (req, res) => {
    const id = req.params.id

    // Verifica se o ID é válido
    if (!mongoose.Types.ObjectId.isValid(id)) {
        return res.status(400).json({ msg: 'ID inválido' })
    }

    const user = await User.findById(id, '-pass')
    if (!user) {
        return res.status(404).json({ msg: 'Usuário não encontrado' })
    }

    res.status(200).json({ user })
})

// Função de verificação do token
function checkToken(req, res, next) {
    const authHeader = req.headers['authorization']
    console.log('Authorization Header:', authHeader) // Log para verificar o cabeçalho

    const token = authHeader && authHeader.split(" ")[1]

    if (!token) {
        return res.status(401).json({ msg: 'Acesso Negado!' })
    }

    try {
        const secret = process.env.SECRET
        jwt.verify(token, secret)  // Verifica o token com a chave secreta
        next()

    } catch (error) {
        console.error('Token Verification Error:', error) // Log para capturar o erro específico
        res.status(400).json({ msg: 'Token Inválido!' })
    }
}

// Rota para cadastrar um novo usuário
app.post('/cadastro', async (req, res) => {
    const { name, pass, confpass } = req.body

    if (!name) {
        return res.status(422).json({ msg: 'Campo nome não pode estar vazio' })
    }

    if (!pass) {
        return res.status(422).json({ msg: 'Campo senha não pode estar vazio' })
    }

    if (pass !== confpass) {
        return res.status(422).json({ msg: 'As senhas não conferem' })
    }

    // Verifica se o usuário já existe
    const userExists = await User.findOne({ name: name })
    if (userExists) {
        return res.status(422).json({ msg: 'Usuário já existente' })
    }

    // Criptografa a senha
    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(pass, salt)

    // Cria o novo usuário
    const user = new User({
        name,
        pass: passwordHash,
    })

    try {
        await user.save()
        res.status(201).json({ msg: 'Usuário criado com sucesso' })
    } catch (error) {
        res.status(500).json({ msg: error })
    }
})

// Rota para login de usuário
app.post('/login', async (req, res) => {
    const { name, pass } = req.body

    if (!name) {
        return res.status(422).json({ msg: 'Campo nome não pode estar vazio' })
    }

    if (!pass) {
        return res.status(422).json({ msg: 'Campo senha não pode estar vazio' })
    }

    // Verifica se o usuário existe
    const userExists = await User.findOne({ name: name })
    if (!userExists) {
        return res.status(422).json({ msg: 'Usuário não encontrado' })
    }

    // Compara a senha
    const checasenha = await bcrypt.compare(pass, userExists.pass)
    if (!checasenha) {
        return res.status(422).json({ msg: 'Senha inválida' })
    }

    try {
        // Gera o token de autenticação
        const secret = process.env.SECRET
        const token = jwt.sign({
            id: userExists._id
        }, secret, { expiresIn: '1h' }) // Token expira em 1 hora

        console.log('Token Gerado:', token) // Log para ver o token gerado
        res.status(200).json({ msg: 'Autenticação realizada', token })
    } catch (error) {
        res.status(500).json({ msg: error })
    }
})

// Conexão com o banco de dados MongoDB
const dbUser = process.env.DB_USER
const dbPass = process.env.DB_PASS

mongoose.connect(`mongodb+srv://${dbUser}:${dbPass}@cluster0.3fgnb.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`)
    .then(() => {
        app.listen(3000, () => console.log('Servidor rodando na porta 3000'))
        console.log('Conectado ao banco de dados!')
    })
    .catch((err) => console.log('Erro na conexão:', err))
