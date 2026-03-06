import { User } from "@/types/types";
import { createContext, useContext, useEffect, useState } from "react";
import { UserLogin, UserVerify,CurrentUser, UserLogout } from "../services/AuthService";
import AsyncStorage from "@react-native-async-storage/async-storage";

export interface AuthContextType {
  user: User | null;
  loading:boolean;
  login:(username:string,password:string)=>void;
  logout:()=>void;
  isAuthenticated:boolean | null;
}

export const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider = ({ children }: { children: React.ReactNode }) => {

  const [user, setUser] = useState<User | null>(null);
  const [loading,setLoading] = useState(false);
  const [isAuthenticated,setIsAuthenticated]=useState<boolean|null>(false);

   useEffect(()=>{
    const checkUser = async()=>{
      try {
        setLoading(true);
        const userRes = await CurrentUser();
        setIsAuthenticated(true);
        console.log(userRes.data.user);
        setUser(userRes.data.user);
      } catch (error) {
         setIsAuthenticated(false);
        console.log(error);
      }
      finally{

        setLoading(false);
      }
    }
    checkUser();
  },[])


  const login = async(username:string,password:string)=>{
    try {
      setLoading(true);
      const response = await UserLogin(username,password);
      if(response.data.success){
        setIsAuthenticated(true);
        if (response.data.accessToken) {
          await AsyncStorage.setItem("accessToken", response.data.accessToken);
        }
        if (response.data.refreshToken) {
          await AsyncStorage.setItem("refreshToken", response.data.refreshToken);
        }
        const userRes = await CurrentUser();
        console.log(userRes.data.user);

        setUser(userRes.data.user);
      }

    } catch (error) {
       console.log(error);
    }
    finally{
      setLoading(false);
    }

  }

  const logout = async()=>{
    try {
      await UserLogout();
      setIsAuthenticated(false);
      await AsyncStorage.removeItem("accessToken");
      await AsyncStorage.removeItem("refreshToken");
      setUser(null);
    } catch (error) {
      console.log(error);
    }
  }


  return (
    <AuthContext.Provider value={{ user,loading,login,logout ,isAuthenticated}}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);

  if (!context) {
    throw new Error("useAuth must be used inside AuthProvider");
  }

  return context;
};
