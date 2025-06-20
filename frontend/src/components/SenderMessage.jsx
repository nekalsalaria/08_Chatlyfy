import React from "react";
import dp1 from "../assets/dp1.jpg";
import { useRef } from "react";
import { useEffect } from "react";
import { useSelector } from "react-redux";

function SenderMessage({ image, message }) {
  let scroll = useRef();
  let { userData } = useSelector((state) => state.user);
  useEffect(() => {
    scroll.current.scrollIntoView({ behaviour: "smooth" });
  }, [message, image]);

  const handleImageScroll = () => {
    scroll?.current.scrollIntoView({ behaviour: "smooth" });
  };
  return (
    <div
      className=" flex items-start gap-[10px]"
    >

      <div ref={scroll} className="w-fit
     max-w-[500px] bg-[#1797C2] 
     px-[20px]  py-[10px] text-white text-[19px]
     relative right-0 ml-auto gap-[10px] shadow-gray-400  rounded-tr-none rounded-2xl">
        {image && (
          <img
            src={image}
            alt=""
            className="w-[150px] flex flex-col  rounded-lg  "
            onLoad={handleImageScroll}
          />
        )}
        {message && <span>{message}</span>}
      </div>
      <div
        className="w-[40px] h-[40px] rounded-full
                  overflow-hidden flex justify-center items-center shadow-lg shadow-gray-500 cursor-pointer bg-white"
       
      >
        <img
          src={userData.image || dp1}
          alt=""
          className="w-full h-full object-cover overflow-hidden"
        />
      </div>
    </div>
  );
}

export default SenderMessage;
