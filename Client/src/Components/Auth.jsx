import { createContext, useContext, useState } from "react";
import { login, verifyRegNo, currentUser } from "../services/AuthService";

export const AuthContext = createContext();

export const AuthContextProvider = ({children})=>{

  const [user, setUser] = useState(null);
  const [isVerifed,setIsVerifed] = useState(null);
  const [loading, setLoading] = useState(true);

  const VerifyUser =  async (userData)=>{
    try {
      const response = await verifyRegNo(userData);
      setIsVerifed(response.data);
    } catch (error) {
      console.log(error);
    }
    finally{
      setLoading(false);
      setIsVerifed(null);
    }
  }

  const UserLogin = async (username,password)=>{
    try {
      const response = await login(username, password);
      const resData = response.data || response;
      if(resData.success){
        const userRes = await currentUser();
        console.log(userRes.data.user);
        setUser(userRes.data?.user || userRes.data || userRes);
      }
    } catch (error) {
      console.log("Unable to Connect Server Right now");
      setUser(null);
    }
    finally{
      setLoading(false);
    }
  }

  return <AuthContext.Provider value={{VerifyUser,user,isVerifed,loading,UserLogin}}>
   {children}
  </AuthContext.Provider>
}

export const useAuth = ()=>{
  const context = useContext(AuthContext);
  if(!context){
    console.log("useAuth must be used within an AuthContextProvider")
  }
  return context;
}



