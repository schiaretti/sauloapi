import express from "express"
import publicRoutes from './routes/public.js'
import cors from 'cors'

const app = express()

app.use(cors())
app.use(express.json())
app.use('/', publicRoutes)



app.listen(3000, () => console.log("servidor rodando!"))