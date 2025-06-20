import { useState } from 'react'
import {useNavigate} from 'react-router-dom'
import axios from 'axios'
import { serverUrl } from '../main'
import { useDispatch, useSelector } from 'react-redux'
import { setUserData } from '../redux/userSlice'

function SignUp() {
  let navigate=useNavigate()
  let [userName,setUserName]=useState('')
  let [email,setEmail]=useState('')
  let [password,setPassword]=useState('')
  let [loading,setLoading]=useState(false)
  let [error,setError]=useState("")
  let dispatch=useDispatch()
  

  const handleSignUp=async(e)=>{
    e.preventDefault()
    setLoading(true)
    try {
      let result=await axios.post(`${serverUrl}/api/auth/signup`,{
        userName,email,password
      },{withCredentials:true})
      dispatch(setUserData(result.data))
      navigate('/profile')
      setEmail('')
      setPassword('')
      setLoading(false)
      setError('')
    } catch (error) {
      console.log(error)
      setLoading(false)
      setError(error?.response?.data?.message)
    }
  }
  return (
    <div className='w-full h-[100vh] bg-slate-200 flex items-center justify-center'>
     <div className='w-full max-w-[500px] h-[600px] bg-white rounded-lg
     shadow-gray-400 shadow-lg flex flex-col gap-[30px]'>
      <div className='w-full h-[200px] bg-[#19cdff] rounded-b-[30%] 
      shadow-gray-400 shadow-lg flex items-center justify-center'>
        <h1 className='text-gray-600 font-bold text-[30px]'>Welcome to  
          <span className='text-white'> chatly</span></h1>
      </div>
      <form className='w-full flex flex-col gap-[20px] items-center' onSubmit={handleSignUp}>
      <input type="text" placeholder='Username' className='w-[90%] h-[50px] outline-none border-2 border-[#20c7ff] px-[20px] 
      py-[10px] bg-white rounded-lg shadow-lg text-gray-700 text-[19px]' onChange={(e)=>setUserName(e.target.value)} value={userName}/>
      <input type="email" placeholder='email' className='w-[90%] h-[50px] outline-none border-2 border-[#20c7ff] px-[20px] 
      py-[10px] bg-white rounded-lg shadow-lg text-gray-700 text-[19px]' onChange={(e)=>setEmail(e.target.value)} value={email}/>
      <input type="password" placeholder='password' className='w-[90%] h-[50px] outline-none border-2 border-[#20c7ff] px-[20px] 
      py-[10px] bg-white rounded-lg shadow-lg text-gray-700 text-[19px]' onChange={(e)=>setPassword(e.target.value)} value={password}/>


            {error && <p className='text-red-500'>{error}</p>}

      <button className='px-[20px] py-[10px] bg-[#19cdff] rounded-2xl
      shadow-gray-400 shadow-lg text-[20px] w-[200px] mt-[20px] font-semibold hover:shadow-inner' disabled={loading}>{loading? "Loading...":"Sign up"}</button>
      <p className='cursor-pointer' onClick={()=>{
        navigate('/login')
      }} >Already Have An Account ? <span className='text-[#20c7ff]'>Login</span></p>
     </form>
     </div>
    </div>
  )
}

export default SignUp
