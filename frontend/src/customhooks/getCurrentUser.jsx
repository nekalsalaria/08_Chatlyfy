import { useEffect } from "react";
import axios from "axios";
import {serverUrl} from '../main'
import { useDispatch, useSelector } from "react-redux";
import { setUserData } from "../redux/userSlice";

const useGetCurrentUser = () => {
    const dispatch = useDispatch();
    const { userData } = useSelector(state => state.user);
    useEffect(() => {
        const fetchUser = async () => {
            try {
                const result = await axios.get(`${serverUrl}/api/user/current`, {
                    withCredentials: true
                });
                dispatch(setUserData(result.data));
            } catch (error) {
                console.log(error);
                console.log("UserID in req:", req.userId);
            }
        };
        fetchUser();
    }, [dispatch]);
    return userData;
};

export default useGetCurrentUser;
