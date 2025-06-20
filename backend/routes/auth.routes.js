import express from 'express'
import { Login, logout, signup } from '../controllers/auth.controllers.js'

const authRouter=express.Router()

authRouter.post('/signup',signup)
authRouter.post('/login',Login)
authRouter.get('/logout',logout)

export default authRouter