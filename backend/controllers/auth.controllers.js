import User from '../models/user.model.js'
import bcrypt from 'bcryptjs'
import genToken from '../config/token.js'


//signup
export const signup = async (req, res) => {
    try {
        const { userName, email, password } = req.body;
        const checkUserByUserName = await User.findOne({ userName });
        if (checkUserByUserName) {
            return res.status(400).json({ message: "username already exists" });
        }
        const checkUserByUserEmail = await User.findOne({ email });
        if (checkUserByUserEmail) {
            return res.status(400).json({ message: "email already exists" });
        }

        if(password.length<6){
            return res.status(400).json({ message: "Password must be atleast 6 characters" });
        }

        const hashedPassword = await bcrypt.hash(password,10)

        const user = await User.create({
            userName,email,password:hashedPassword
        })

        const token= await genToken(user._id)

        res.cookie("token",token,{
            httpOnly:true,
            maxAge:7*24*60*60*1000,
            sameSite:"Lax",
            secure:false
        })

        return res.status(201).json(user)

    } catch (error) {
        return res.status(500).json({ message: "Signup error" });
    }
}

//login
export const Login = async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: "User does not exists" });
        }

        const isMatch= await bcrypt.compare(password,user.password)
        if(!isMatch){
            return res.status(400).json({ message: "incorrect password" });
        }

        const token= await genToken(user._id)

        res.cookie("token",token,{
            httpOnly:true,
            maxAge:7*24*60*60*1000,
            sameSite:"Lax",
            secure:false
        })

        return res.status(200).json(user)

    } catch (error) {
        return res.status(500).json({ message: "login error" });
    }
}

//Logout
export const logout = async (req,res)=>{
    try {
        res.clearCookie("token")
        return res.status(200).json({message:"logout successfully"})
    } catch (error) {
        return res.status(500).json({ message: "logout error" });
    }
}
