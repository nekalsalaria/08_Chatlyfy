import uploadOnCloudinary from '../config/cloudinary.js'
import Conversation from '../models/conversation.model.js'
import Message from '../models/message.model.js'
import { getReceiverSocketId, io } from '../socket/socket.js'


export const sendMessage = async (req, res) => {
    try {
        let sender = req.userId
        let { receiver } = req.params
        let { message } = req.body

        console.log("Sender:", sender)
        console.log("Receiver:", receiver)
        console.log("Message:", message)
        console.log("File:", req.file)

        let image
        if (req.file) {
            image = await uploadOnCloudinary(req.file.path)
            console.log("Uploaded Image URL:", image)
        }

        let conversation = await Conversation.findOne({
            participants: { $all: [sender, receiver] }
        })

        let newMessage = await Message.create({
            sender, receiver, message, image
        })

        if (!conversation) {
            conversation = await Conversation.create({
                participants: [sender, receiver],
                messages: [newMessage._id]
            })
        } else {
            conversation.messages.push(newMessage._id)
            await conversation.save()
        }

        const receiverSocketId=getReceiverSocketId(receiver)
        if(receiverSocketId){
            io.to(receiverSocketId).emit("newMessage",newMessage)
        }

        return res.status(201).json(newMessage)

    } catch (error) {
        console.error("🔥 Send Message Error:", error)
        return res.status(500).json({ message: `send Message error ${error}` })
    }
}


export const getMessage = async (req, res) => {
    try {
        let sender = req.userId
        let {receiver}=req.params
        let conversation = await Conversation.findOne({
            participants: { $all: [sender, receiver] }
        }).populate("messages")

        if (!conversation) {
            return res.status(400).json({ message: "conversation is not found" })
        }

        return res.status(200).json(conversation?.messages)
    } catch (error) {
        return res.status(500).json({ message: `get Message error ${error}` })
    }
}