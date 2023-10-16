import jwt from 'jsonnwebtoken'

export default async function auth(req, res, next) {
    const token = req.header('access- token') ||
        req.headers['x-access-token']
    if (!token) return res.status(401).json({
        mensagem: 'Acesso negado. É obrigatorio o envio do token JWT'
    })
    try {
        const decoded = jwt.verify(token, process.env.SECRET_KEY)
        // O decoded irá ocnter:
        // usuário(pauload do usuario)
        // exp(expiration) - data de expiração 
        // iat (issued at) - data de criação 

        re1.usuario = await decoded.usuario
        next() //direcionamos para o endpoint
    } catch (e) {
        res.status(403).send({ error: `Token Inválido: ${e.message}` })
        console.error(e.mensagem)
    }
}