import Image from "next/image";
import {
  bgimg,
  img1,
  img2,
  sigin,
  group,
  short,
  circle,
  Qcircle,
  link
} from "../constants/constants";

import Link from "next/link";
import TrialPage from "../../../[components]/trial/TrialPage";

export default async function Home() {
  return (
    <div
      className="bg-cover bg-center h-100%  w-100%"
      style={{
        backgroundImage: `url(${bgimg.src})`,
      }}
    >
      <div className="pt-12">
        <div>
          <div className="flex justify-between">
            <Image src={img1} alt="Linkly" className="flex ml-12" />
            <div className="mr-12 flex">
              <div className="flex w-[150px] h-[60px] bg-slate-600 rounded-3xl mr-4 cursor-pointer">
                <div className="text-white ml-8 mt-5 h-[18px] w-[43px]  ">
                  <Link href={"/signin"}>
                    <p>Login</p>
                  </Link>
                </div>
                <Image
                  src={sigin}
                  alt="signin-btn"
                  className="w-[20px] h-[28px] mt-4 ml-4"
                />
              </div>
              <div className="h-[60px] w-[178px] rounded-full bg-blue-700 hidden md:block">
                <Link href={"/signup"}>
                  <p className="text-white flex justify-center mt-4 cursor-pointer">
                    Register Now
                  </p>
                </Link>
              </div>
            </div>
          </div>
          <div className="w-100%  flex  flex-col items-center mt-32">
            <Image
              src={short}
              alt="shortner"
              className="w-[330px] h-[82]  sm:hidden"
            />
            <Image
              src={img2}
              alt="123"
              className="w-[566px] h-[81px] hidden md:block"
            />
            <p className="h-[47px] w-[634px] text-white text-center">
              Linkly is an efficient and easy-to-use URL shortening service that
              streamlines your online experience.
            </p>
          </div>
          <div className="flex justify-center mt-10">
            <div className="flex flex-row relative">
              <span className="h-[25px] w-[25] absolute ml-10 mt-8 ">
                <Image src={link} alt="Link" />
              </span>
              <input
                type="text"
                placeholder="                Enter the link here"
                className="w-[660px] h-[76px] rounded-[48px] border-[4px] border-gray-400 bg-slate-800 text-white  text-[30px] px-5"
              />
              <Image
                src={circle}
                alt="crcle"
                className="ml-[576px] h-[110px] w-[115px] absolute cursor-pointer -mt-[7px] sm:hidden"
              />

              <button className="hidden  md:block w-[178px] h-[65px] rounded-[100px]  border-[1px] bg-blue-700 text-white ml-[480px] mt-2 absolute cursor-pointer">
                <Link href={"/add"}>Shorten Now!</Link>
              </button>
            </div>
          </div>
          <div className="flex mt-8 justify-center ">
            <Image src={group} alt="" className="" />
            <p className="text-white mt-1">Auto Paste to Clipboard </p>
          </div>
          <p className="text-white flex justify-center mt-5">
            You can create <span className="text-red-700 ml-1 mr-1"> 05 </span>{" "}
            more links. Register Now to enjoy Unlimited usage
            <Image src={Qcircle} alt="circle" className="ml-3 " />
          </p>
        </div>
      </div>
      <div className="flex justify-center mt-5">
        <TrialPage />
      </div>
      <div className="h-[148px] w-full bg-transparent  flex justify-center items-center">
        <div className="flex justify-center ">
          <div className="w-[230  px] h-[10px] text-white flex justify-end">
            <Link href={"/main"} className="text-blue-700 underline">
              Detail _
            </Link>
            _to enjoy Ulimited History
          </div>
        </div>
      </div>
    </div>
  );
}
