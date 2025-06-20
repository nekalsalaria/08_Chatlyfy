import express from 'express'
import dotenv from 'dotenv'
import connectDb from './config/db.js'
import authRouter from './routes/auth.routes.js'
import cookieParser from 'cookie-parser'
import userRouter from './routes/user.routes.js'
dotenv.config()
import cors from 'cors'
import messageRouter from './routes/message.route.js'
import { app, server } from './socket/socket.js'

const port = process.env.PORT || 5000


app.use(cors({
    origin:"https://chatlyfy.onrender.com",
    credentials:true
}))
app.use(express.json())
app.use(cookieParser())
app.use('/api/auth',authRouter)
app.use('/api/user',userRouter)
app.use('/api/message',messageRouter)

server.listen(port,()=>{
    connectDb()
    console.log("server is runing")
})
