import express from 'express'
import { editprofile, getCurrentUser, getOtherUsers, search } from '../controllers/user.cotroller.js'
import isAuth from '../middleware/isAuth.js'
import { uplaod } from '../middleware/multer.js'

const userRouter=express.Router()

userRouter.get('/current', isAuth, getCurrentUser)
userRouter.get('/others', isAuth, getOtherUsers)
userRouter.get('/search', isAuth, search)
userRouter.put('/profile', isAuth, uplaod.single("image") 
,editprofile)


export default userRouter