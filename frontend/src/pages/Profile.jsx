import React from "react";
import dp1 from "../assets/dp1.jpg";
import { MdOutlineCameraAlt } from "react-icons/md";
import { useDispatch, useSelector } from "react-redux";
import { IoArrowBack, IoHandLeft } from "react-icons/io5";
import { useNavigate } from "react-router-dom";
import { useState } from "react";
import { useRef } from "react";
import axios from 'axios'
import {serverUrl} from '../main'
import { setUserData } from "../redux/userSlice";

function Profile() {
  let { userData } = useSelector((state) => state.user);
  let dispatch = useDispatch()
  let navigate = useNavigate();
  let [name, setName] = useState(userData.name || "");
  let [frontendImage, setFrontendImage] = useState(userData.image || dp1);
  let [backendImage, setBackendImage] = useState(null);
  let image = useRef();
  let [saving,setSaving]=useState(false)

  const handleImage=(e)=>{
    let file=e.target.files[0]
    setBackendImage(file)
    setFrontendImage(URL.createObjectURL(file))
  }
  const handleProfile=async (e)=>{
    e.preventDefault()
     setSaving(true)
    try {
      let formData=new FormData()
      formData.append("name",name)
      if(backendImage){
      formData.append("image",backendImage)
      }

      let result= await axios.put(`${serverUrl}/api/user/profile`,formData,{withCredentials:true})
       setSaving(false)

      dispatch(setUserData(result.data))
      navigate('/')
    } catch (error) {
      console.log(error)
      setSaving(false)
    }
  }


  return (
    <div className="w-full min-h-screen bg-gradient-to-br from-sky-100 to-blue-200 flex flex-col justify-center items-center py-10">
      <div
        className="cursor-pointer fixed top-[20px] left-[20px] "
        onClick={() => navigate("/")}
      >
        <IoArrowBack className="w-[50px] h-[50px] text-gray-500" />
      </div>
      <div className="bg-white rounded-xl shadow-xl p-8 flex flex-col items-center w-full max-w-md">
        <div
          className="w-[140px] h-[140px] bg-white rounded-full border-4 border-[#20c7ff] shadow-lg relative flex items-center justify-center mb-6"
          onClick={() => image.current.click()}
        >
          <img
            src={frontendImage}
            alt="Profile"
            className="w-[128px] h-[128px] rounded-full object-cover"
          />
          <button className="absolute bottom-2 right-2 bg-white p-2 rounded-full shadow hover:bg-[#20c7ff] hover:text-white transition-colors">
            <MdOutlineCameraAlt className="w-6 h-6 text-gray-700" />
          </button>
        </div>
        <form className="w-full flex flex-col gap-4" onSubmit={handleProfile}>
          <input type="file" hidden accept="image/*" ref={image} onChange={handleImage} />
          <div>
            <input
              type="text"
              placeholder="Enter your name"
              className="w-full px-4 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-[#20c7ff] bg-slate-50"
              onChange={(e) => setName(e.target.value)}
              value={name}
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Username
            </label>
            <input
              type="text"
              readOnly
              value={userData?.userName}
              className="w-full px-4 py-2 border rounded-lg bg-gray-100 text-gray-400 cursor-not-allowed"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Email
            </label>
            <input
              type="email"
              readOnly
              value={userData?.email}
              className="w-full px-4 py-2 border rounded-lg bg-gray-100 text-gray-400 cursor-not-allowed"
            />
          </div>
          <button
            type="submit"
            className="mt-4 bg-[#20c7ff] text-white py-2 rounded-lg font-semibold hover:bg-[#1ba6d8] transition-colors"
          disabled={saving}>
            {saving?"Saving...":"Save Profile"}
          </button>
        </form>
      </div>
    </div>
  );
}

export default Profile;
