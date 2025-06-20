import { useEffect } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { Route, Routes, Navigate } from 'react-router-dom';
import Login from './pages/Login';
import SignUp from './pages/SignUp';
import Home from './pages/Home';
import Profile from './pages/Profile';
import axios from 'axios';
import { setOnlineUsers, setSocket, setUserData } from './redux/userSlice';
import { serverUrl } from './main';
import getOtherUsers from './customhooks/getOtherUser';
import {io} from 'socket.io-client'

function App() {
  getOtherUsers()
  const dispatch = useDispatch();
  let { userData,socket,onlineUsers } = useSelector(state => state.user);

  useEffect(()=>{

    if(userData){
      const socketio = io(`${serverUrl}`,{
      query:{
        userId:userData?._id
      }
    })

    dispatch(setSocket(socketio))

    socketio.on("getOnlineUsers",(users)=>{
      dispatch(setOnlineUsers(users))
    })

    return ()=>socketio.close()
    }else {
      if(socket){
        socket.close()
        dispatch(setSocket(null))
      }
    }
  },[userData])

  // ✅ Fire getCurrentUser once
  useEffect(() => {
    const fetchUser = async () => {
      try {
        const res = await axios.get(`${serverUrl}/api/user/current`, {
          withCredentials: true,
        });
        dispatch(setUserData(res.data));
      } catch (err) {
        console.log("Error fetching current user", err?.response?.data || err.message);
      }
    };
    fetchUser();
  }, [dispatch]);

  return (
    <Routes>
      <Route path='/login' element={!userData ? <Login /> : <Navigate to="/" />} />
      <Route path='/signup' element={!userData ? <SignUp /> : <Navigate to="/profile" />} />
      <Route path='/' element={userData ? <Home /> : <Navigate to="/login" />} />
      <Route path='/profile' element={userData ? <Profile /> : <Navigate to="/signup" />} />
    </Routes>
  );
}

export default App;
