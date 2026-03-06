import { User } from "@/types/types";
import { createContext, useContext, useEffect, useState } from "react";
import { UserLogin,CurrentUser, UserLogout } from "../services/AuthService";
import AsyncStorage from "@react-native-async-storage/async-storage";

export interface AuthContextType {
  user: User | null;
  loading:boolean;
  login:(username:string,password:string)=>void;
  logout:()=>void;
  isAuthenticated:boolean | null;
  error:string | null
}

export const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider = ({ children }: { children: React.ReactNode }) => {

  const [user, setUser] = useState<User | null>(null);
  const [loading,setLoading] = useState(false);
  const [isAuthenticated,setIsAuthenticated]=useState<boolean|null>(false);
  const [error,setError]=useState<string | null>(null);

   useEffect(()=>{
    const checkUser = async()=>{
      try {
        setLoading(true);
        const userRes = await CurrentUser();
        setIsAuthenticated(true);
        setUser(userRes.data.user);
      } catch (error:any) {
         setIsAuthenticated(false);
        setError(error?.response?.data?.message)
      }
      finally{

        setLoading(false);
      }
    }
    checkUser();
  },[])


  const login = async(username:string,password:string)=>{
  try {

    setLoading(true)
    setError(null)

    const response = await UserLogin(username,password)

    if(response.data.success){

      setIsAuthenticated(true)

      if (response.data.accessToken) {
        await AsyncStorage.setItem("accessToken", response.data.accessToken)
      }

      if (response.data.refreshToken) {
        await AsyncStorage.setItem("refreshToken", response.data.refreshToken)
      }

      const userRes = await CurrentUser()

      setUser(userRes.data.user)

    }

  } catch (err:any) {

    setError(err?.response?.data?.message || "Login failed")

  } finally {

    setLoading(false)

  }
}

  const logout = async()=>{
    try {
      setLoading(true)
      await UserLogout();
      await AsyncStorage.removeItem("accessToken");
      await AsyncStorage.removeItem("refreshToken");
      setUser(null);
      setIsAuthenticated(false);
    } catch (error) {
      console.log(error);
    }finally{
      setLoading(false);
    }
  }


  return (
    <AuthContext.Provider value={{ user,loading,login,logout ,isAuthenticated,error}}>
      {children}
    </AuthContext.Provider>
  );
};
 const useAuth = () => {
  const context = useContext(AuthContext);

  if (!context) {
    throw new Error("useAuth must be used inside AuthProvider");
  }

  return context;
};

export default useAuth;
