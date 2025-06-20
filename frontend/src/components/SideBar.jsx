import React, { useState } from "react";
import { useDispatch, useSelector } from "react-redux";
import dp1 from "../assets/dp1.jpg";
import { IoSearchSharp } from "react-icons/io5";
import { RiLogoutCircleLine } from "react-icons/ri";
import { RxCross2 } from "react-icons/rx";
import axios from "axios";
import { serverUrl } from "../main";
import {
  setOtherUsers,
  setSelectedUser,
  setUserData,
} from "../redux/userSlice";
import { useNavigate } from "react-router-dom";

function SideBar() {
  let { userData, otherUsers, selectedUser, onlineUsers } = useSelector(
    (state) => state.user
  );
  let [search, setSearch] = useState(false);
  let dispatch = useDispatch();
  let navigate = useNavigate();

  const handleLogout = async () => {
    try {
      let result = await axios.get(`${serverUrl}/api/auth/logout`, {
        withCredentials: true,
      });
      dispatch(setUserData(null));
      dispatch(setOtherUsers(null));
      navigate("/login");
    } catch (error) {
      console.log(error);
    }
  };
  const handlesearch = async () => {
    try {
      let result = await axios.get(`${serverUrl}/api/user/search?query=${input}`, {
        withCredentials: true,
      });
      dispatch(setUserData(null));
      dispatch(setOtherUsers(null));
      navigate("/login");
    } catch (error) {
      console.log(error);
    }
  };

  return (
    <div
      className={`lg:w-[30%] overflow-hidden lg:block ${
        !selectedUser ? "block" : "hidden"
      } w-full h-full bg-slate-200 relative`}
    >
      {/* Top Section */}
      <div
        className="w-full h-[300px] bg-[#19cdff] rounded-b-[30%] 
        shadow-gray-400 shadow-lg flex flex-col justify-center
        px-[20px]"
      >
        <h1 className="text-white font-semibold text-[25px]">Chatlyfy</h1>
        <div className="w-full flex justify-between items-center">
          <h1 className="text-gray-800 font-bold text-[25px]">
            Hii , {userData.name || "user"}
          </h1>
          <div
            className="w-[60px] h-[60px] rounded-full
            overflow-hidden flex justify-center items-center shadow-lg shadow-gray-500 cursor-pointer bg-white"
            onClick={() => navigate("/profile")}
          >
            <img
              src={userData.image || dp1}
              alt=""
              className="w-full h-full object-cover overflow-hidden"
            />
          </div>
        </div>

        <div className="w-full flex items-center gap-[20px]">
          {!search && (
            <div
              className="w-[60px] h-[60px] rounded-full
              overflow-hidden flex justify-center items-center shadow-gray-500 shadow-lg bg-white mt-[10px]"
              onClick={() => setSearch(true)}
            >
              <IoSearchSharp className="w-[25px] h-[25px] cursor-pointer" />
            </div>
          )}

          {search && (
            <form className="w-full h-[60px] shadow-gray-500 shadow-lg bg-white flex items-center gap-[10px] mt-[10px] 
            rounded-full overflow-hidden px-[20px]">
              <IoSearchSharp className="w-[25px] h-[25px]" />
              <input
                type="text"
                placeholder="search Users....."
                className="w-full h-full p-[10px] outline-0 border-0 text-[17px]"
              />
              <RxCross2
                className="w-[25px] h-[25px] cursor-pointer "
                onClick={() => {
                  setSearch(false);
                }}
              />
            </form>
          )}

          {!search &&
            otherUsers?.map(
              (user) =>
                onlineUsers?.includes(user._id) && (
                  <div
                    key={user._id}
                    className="w-[60px] h-[60px] rounded-full mt-[10px] relative
                    overflow-hidden flex justify-center items-center cursor-pointer shadow-lg bg-white shadow-gray-500"  onClick={() => {
              dispatch(setSelectedUser(user));
            }}
                  >
                    <img
                      src={user.image || dp1}
                      alt=""
                      className="w-full h-full object-cover overflow-hidden"
                    />
                    <span className="w-[12px] h-[12px] bg-[#3aff20] rounded-full border-2 border-white absolute bottom-3 right-1"></span>
                  </div>
                )
            )}
        </div>
      </div>

      {/* Scrollable User List */}
      <div className="w-full h-[calc(100vh-360px)] overflow-auto flex flex-col gap-[20px] items-center mt-[20px] px-[10px] pb-[80px]">
        {otherUsers?.map((user) => (
          <div
            key={user._id}
            className="w-[95%] h-[60px] flex justify-start 
            items-center gap-[20px] shadow-gray-500 bg-white shadow-lg rounded-full hover:bg-[#78cae5] cursor-pointer"
            onClick={() => {
              dispatch(setSelectedUser(user));
            }}
          >
            <div
              className="w-[60px] h-[60px] rounded-full mt-[10px] relative
              overflow-hidden flex justify-center items-center shadow-lg bg-white shadow-gray-500"
            >
              <img
                src={user.image || dp1}
                alt=""
                className="w-full h-full object-cover overflow-hidden"
              />
              {onlineUsers?.includes(user._id) && (
                <span className="w-[10px] h-[10px] rounded-full bg-[#3aff20] absolute bottom-3 right-1"></span>
              )}
            </div>
            <h1 className="text-gray-800 font-bold text-[20px]">
              {user.name || user.userName}
            </h1>
          </div>
        ))}
      </div>

      {/* Logout Button (Fixed at Bottom) */}
      <div
        className="w-[60px] h-[60px] rounded-full
        overflow-hidden flex justify-center items-center bg-[#19cdff] shadow-gray-500 shadow-lg
        fixed bottom-[20px] left-[10px] cursor-pointer"
        onClick={handleLogout}
      >
        <RiLogoutCircleLine className="w-[25px] h-[25px]" />
      </div>
    </div>
  );
}

export default SideBar;
