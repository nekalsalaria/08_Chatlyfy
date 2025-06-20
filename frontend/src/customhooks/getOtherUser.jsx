import { useEffect } from "react";
import axios from "axios";
import {serverUrl} from '../main'
import { useDispatch, useSelector } from "react-redux";
import { setOtherUsers } from "../redux/userSlice";

const getOtherUsers = () => {
    const dispatch = useDispatch();
    const { userData } = useSelector(state => state.user);
    useEffect(() => {
        const fetchUser = async () => {
            try {
                const result = await axios.get(`${serverUrl}/api/user/others`, {
                    withCredentials: true
                })
                dispatch(setOtherUsers(result.data));
            } catch (error) {
                console.log(error);
                console.log("UserID in req:", req.userId);
            }
        };
        fetchUser();
    }, [userData]);
};

export default getOtherUsers;
