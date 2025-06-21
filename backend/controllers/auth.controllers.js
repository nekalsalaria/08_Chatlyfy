import User from '../models/user.model.js'
import bcrypt from 'bcryptjs'
import genToken from '../config/token.js'

// Signup
export const signup = async (req, res) => {
    try {
        const { userName, email, password } = req.body;

        // Check if username exists
        const checkUserByUserName = await User.findOne({ userName });
        if (checkUserByUserName) {
            return res.status(400).json({ message: "Username already exists" });
        }

        // Check if email exists
        const checkUserByUserEmail = await User.findOne({ email });
        if (checkUserByUserEmail) {
            return res.status(400).json({ message: "Email already exists" });
        }

        // Basic length check
        if (password.length < 6) {
            return res.status(400).json({ message: "Password must be at least 6 characters" });
        }

        // ✅ Strong password pattern check
        const passwordRegex = /^(?=.*[a-zA-Z])(?=.*[0-9])(?=.*[@#$%^&+=!]).{6,}$/;
        if (!passwordRegex.test(password)) {
            return res.status(400).json({
                message: "Password must include letters, numbers, and a special character like @12as"
            });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create user
        const user = await User.create({
            userName,
            email,
            password: hashedPassword
        });

        // Generate JWT token
        const token = await genToken(user._id);

        // Set cookie
        res.cookie("token", token, {
            httpOnly: true,
            maxAge: 7 * 24 * 60 * 60 * 1000,
            sameSite: "Lax",
            secure: false
        });

        return res.status(201).json(user);

    } catch (error) {
        return res.status(500).json({ message: "Signup error" });
    }
};

// Login
export const Login = async (req, res) => {
    try {
        const { email, password } = req.body;

        // Check if user exists
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: "User does not exist" });
        }

        // Compare password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: "Incorrect password" });
        }

        // Generate JWT token
        const token = await genToken(user._id);

        // Set cookie
        res.cookie("token", token, {
            httpOnly: true,
            maxAge: 7 * 24 * 60 * 60 * 1000,
            sameSite: "Lax",
            secure: false
        });

        return res.status(200).json(user);

    } catch (error) {
        return res.status(500).json({ message: "Login error" });
    }
};

// Logout
export const logout = async (req, res) => {
    try {
        res.clearCookie("token");
        return res.status(200).json({ message: "Logout successfully" });
    } catch (error) {
        return res.status(500).json({ message: "Logout error" });
    }
};
