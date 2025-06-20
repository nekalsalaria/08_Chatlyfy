import {useNavigate} from 'react-router-dom'
import axios from 'axios'
import { serverUrl } from '../main'
import { useState } from 'react'
import { useDispatch, useSelector } from 'react-redux'
import { setSelectedUser, setUserData } from '../redux/userSlice'


function Login() {
 let navigate=useNavigate()
  let [email,setEmail]=useState('')
  let [password,setPassword]=useState('')
  let [loading,setLoading]=useState(false)
  let [error,setError]=useState("")
  let dispatch=useDispatch()

  const handleLogin=async(e)=>{
    e.preventDefault()
    setLoading(true)
    try {
      let result=await axios.post(`${serverUrl}/api/auth/login`,{
       email,password
      },{withCredentials:true})
      dispatch(setUserData(result.data))
      dispatch(setSelectedUser(null))
      navigate('/')
      setEmail('')
      setPassword('')
      setLoading(false)
      setError('')
    } catch (error) {
      console.log(error)
      setLoading(false)
      setError(error.response.data.message)
    }
  }
  return (
    <div className='w-full h-[100vh] bg-slate-200 flex items-center justify-center'>
     <div className='w-full max-w-[500px] h-[600px] bg-white rounded-lg
     shadow-gray-400 shadow-lg flex flex-col gap-[30px]'>
      <div className='w-full h-[200px] bg-[#19cdff] rounded-b-[30%] 
      shadow-gray-400 shadow-lg flex items-center justify-center'>
        <h1 className='text-gray-600 font-bold text-[30px]'>Login to  
          <span className='text-white'> chatly</span></h1>
      </div>
      <form className='w-full flex flex-col gap-[20px] items-center' onSubmit={handleLogin}>
      <input type="email" placeholder='email' className='w-[90%] h-[50px] outline-none border-2 border-[#20c7ff] px-[20px] 
      py-[10px] bg-white rounded-lg shadow-lg text-gray-700 text-[19px]' onChange={(e)=>setEmail(e.target.value)} value={email}/>
      <input type="password" placeholder='password' className='w-[90%] h-[50px] outline-none border-2 border-[#20c7ff] px-[20px] 
      py-[10px] bg-white rounded-lg shadow-lg text-gray-700 text-[19px]' onChange={(e)=>setPassword(e.target.value)} value={password}/>

      {error && <p className='text-red-500'>{error}</p>}

      <button className='px-[20px] py-[10px] bg-[#19cdff] rounded-2xl
      shadow-gray-400 shadow-lg text-[20px] w-[200px] mt-[20px] font-semibold hover:shadow-inner'>Login</button>
      <p className='cursor-pointer' onClick={()=>{
        navigate('/signup')
      }} >Want to create a new Account ? <span className='text-[#20c7ff]' disabled={loading}>{loading? "Loading...":"Sign up"}</span></p>
     </form>
     </div>
    </div>
  )
}

export default Login
