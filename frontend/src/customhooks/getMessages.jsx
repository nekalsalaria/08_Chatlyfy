import { useEffect } from "react";
import axios from "axios";
import {serverUrl} from '../main'
import { useDispatch, useSelector } from "react-redux";
import { setOtherUsers } from "../redux/userSlice";
import { setMessages } from "../redux/messageSlice";

const getMessage = () => {
    const dispatch = useDispatch();
    const { userData,selectedUser } = useSelector(state => state.user);
    useEffect(() => {
        const fetchMessages = async () => {
            try {
                const result = await axios.get(`${serverUrl}/api/message/get/${selectedUser._id}`, {
                    withCredentials: true
                })
                dispatch(setMessages(result.data));
            } catch (error) {
                console.log(error);
                console.log("UserID in req:", req.userId);
            }
        };
        fetchMessages();
    }, [selectedUser,userData]);
};

export default getMessage;
