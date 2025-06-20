import React, { useRef, useState, useEffect } from "react";
import { IoArrowBack } from "react-icons/io5";
import dp1 from "../assets/dp1.jpg";
import { useDispatch, useSelector } from "react-redux";
import { setSelectedUser } from "../redux/userSlice";
import { RiEmojiStickerLine } from "react-icons/ri";
import { BsImages } from "react-icons/bs";
import { MdOutlineSend } from "react-icons/md";
import EmojiPicker from "emoji-picker-react";
import SenderMessage from "./SenderMessage";
import ReceiverMessage from "./ReceiverMessage";
import { serverUrl } from "../main";
import axios from "axios";
import { setMessages } from "../redux/messageSlice";
import {io} from 'socket.io-client'


function MessageArea() {
  const dispatch = useDispatch();
  const { selectedUser, userData,socket } = useSelector((state) => state.user);
  const { messages } = useSelector((state) => state.message);

  const [showPicker, setShowPicker] = useState(false);
  const [input, setInput] = useState("");
  const [frontendImage, setFrontendImage] = useState(null);
  const [backendImage, setBackendImage] = useState(null);
  const image = useRef();

  // ✅ Fetch messages when selected user changes
  useEffect(() => {
    if (!selectedUser?._id) return;

    dispatch(setMessages([])); // clear old messages

    const fetchMessages = async () => {
      try {
        const result = await axios.get(
          `${serverUrl}/api/message/send/${selectedUser._id}`,
          { withCredentials: true }
        );
        dispatch(setMessages(result.data));
      } catch (error) {
        console.log("Fetch messages error:", error);
      }
    };

    fetchMessages();
  }, [selectedUser, dispatch]);

  // ✅ Handle image preview
  const handleImage = (e) => {
    const file = e.target.files[0];
    if (file) {
      setBackendImage(file);
      setFrontendImage(URL.createObjectURL(file));
    }
  };

  // ✅ Send message
  const handleSendMessage = async (e) => {

    e.preventDefault();
    if (!input.trim() && !backendImage) return;

    try {
      const formData = new FormData();
      formData.append("message", input);
      if (backendImage) formData.append("image", backendImage);

      const result = await axios.post(
        `${serverUrl}/api/message/send/${selectedUser._id}`,
        formData,
        { withCredentials: true }
      );

      dispatch(setMessages([...messages, result.data]));
      setInput("");
      setFrontendImage(null);
      setBackendImage(null);
    } catch (error) {
      console.log("Send message error:", error);
    }
  };

  const onEmojiClick = (emojiData) => {
    setInput((prev) => prev + emojiData.emoji);
    setShowPicker(false);
  };

  useEffect(()=>{
    socket.on("newMessage",(mess)=>{
      dispatch(setMessages([...messages,mess]))
    })
    return ()=>socket.off("newMessage")
  },[messages,setMessages])

  return (
    <div
      className={`lg:w-[70%] relative ${
        selectedUser ? "flex" : "hidden"
      } lg:flex w-full h-full bg-gradient-to-br from-slate-200 to-blue-100 border-l-2 border-gray-300`}
    >
      {selectedUser ? (
        <div className="w-full h-[100vh] flex flex-col">
          {/* Header */}
          <div className="w-full h-[100px] bg-gradient-to-r from-[#31c1e8] to-[#5eead4] rounded-b-[30px] shadow-lg shadow-gray-300 flex items-center gap-6 px-8">
            <button
              className="p-2 rounded-full hover:bg-white/20 transition"
              onClick={() => dispatch(setSelectedUser(null))}
            >
              <IoArrowBack className="w-8 h-8 text-white" />
            </button>
            <div className="w-14 h-14 rounded-full overflow-hidden flex justify-center items-center shadow-lg bg-white border-2 border-[#31c1e8]">
              <img
                src={selectedUser?.image || dp1}
                alt=""
                className="w-full h-full object-cover"
              />
            </div>
            <h1 className="text-white font-bold text-xl drop-shadow">
              {selectedUser?.name || "User"}
            </h1>
          </div>

          {/* Messages */}
          <div className="w-full h-[70%] py-[20px] flex flex-col px-[20px] overflow-auto gap-[20px]  ">
            {showPicker && (
              <div className="absolute bottom-[120px] left-[20px] z-[100]">
                <EmojiPicker
                  width={250}
                  height={350}
                  className="shadow-lg"
                  onEmojiClick={onEmojiClick}
                />
              </div>
            )}

            {messages && messages.map((mess) =>
              mess.sender === userData._id ? (
                <SenderMessage
                  key={mess._id}
                  image={mess.image}
                  message={mess.message}
                />
              ) : (
                <ReceiverMessage
                  key={mess._id}
                  image={mess.image}
                  message={mess.message}
                />
              )
            )}
          </div>

          {/* Input Area */}
          <div className="w-full lg:w-[70%] h-[100px] fixed bottom-[20px] flex items-center justify-center">
            {frontendImage && (
              <img
                src={frontendImage}
                alt=""
                className="w-[80px] absolute bottom-[100px] right-[20%] rounded-lg shadow-gray-400 shadow-lg"
              />
            )}
            <form
              onSubmit={handleSendMessage}
              className="w-[95%] px-[20px] lg:w-[70%] bg-[#1797c2] h-[60px] shadow-lg rounded-full shadow-gray-400 flex items-center gap-[20px]"
            >
              <div onClick={() => setShowPicker((prev) => !prev)}>
                <RiEmojiStickerLine className="w-[25px] h-[25px] text-white cursor-pointer" />
              </div>
              <input
                type="file"
                accept="image/*"
                ref={image}
                hidden
                onChange={handleImage}
              />
              <input
                type="text"
                placeholder="Enter Your Message..."
                className="w-full placeholder-white h-full px-[10px] outline-none border-0 text-[19px] text-white bg-transparent"
                onChange={(e) => setInput(e.target.value)}
                value={input}
              />
              <div onClick={() => image.current.click()}>
                <BsImages className="w-[25px] h-[25px] text-white cursor-pointer" />
              </div>
              <button type="submit">
                <MdOutlineSend className="w-[25px] h-[25px] text-white cursor-pointer" />
              </button>
            </form>
          </div>
        </div>
      ) : (
        // Welcome Screen
        <div className="flex flex-col items-center justify-center w-full h-full">
          <h1 className="text-[50px] font-extrabold text-[#31c1e8] mb-2 drop-shadow">
            Welcome to Chatlyfy
          </h1>
          <span className="text-[30px] text-gray-500">Chat Friendly!</span>
        </div>
      )}
    </div>
  );
}

export default MessageArea;
