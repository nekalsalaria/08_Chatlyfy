import jwt from 'jsonwebtoken';

const isAuth = async (req, res, next) => {
    try {
        const token = req.cookies.token;
        if (!token) {
            return res.status(400).json({ message: "Token is not found" });
        }

        const verifyToken = jwt.verify(token, process.env.JWT_SECRET);
        req.userId = verifyToken.userId;
        next();
    } catch (error) {
        console.error("isAuth error:", error.message);
        res.status(500).json({ message: "isAuth error" });
        console.log("Token:", token);
        console.log("Verified:", verifyToken);

    }
};

export default isAuth;
