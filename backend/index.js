import express from 'express'
import dotenv from 'dotenv'
import connectDb from './config/db.js'
import authRouter from './routes/auth.routes.js'
import cookieParser from 'cookie-parser'
import userRouter from './routes/user.routes.js'
import cors from 'cors'
import messageRouter from './routes/message.route.js'
import { app, server } from './socket/socket.js'

dotenv.config()

const port = process.env.PORT || 5000

// ✅ Allow multiple origins
const allowedOrigins = [
  'http://localhost:5173',
  'https://chatlyfy.onrender.com'
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true
}));

app.use(express.json());
app.use(cookieParser());

app.use('/api/auth', authRouter);
app.use('/api/user', userRouter);
app.use('/api/message', messageRouter);

server.listen(port, () => {
  connectDb();
  console.log('Server is running');
});
