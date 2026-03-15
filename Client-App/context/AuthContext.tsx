import { User } from '@/types/types';
import { createContext, useContext, useEffect, useState } from 'react';
import { UserLogin, CurrentUser, UserLogout } from '../services/AuthService';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { jwtDecode } from 'jwt-decode';
import { useRouter } from 'expo-router';

export interface AuthContextType {
  user: User | null;
  loading: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  isAuthenticated: boolean | null;
  error: string | null;
}

export const AuthContext = createContext<AuthContextType | undefined>(
  undefined
);

export const AuthProvider = ({ children }: { children: React.ReactNode }) => {
  const router = useRouter();
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(false);
  const [isAuthenticated, setIsAuthenticated] = useState<boolean | null>(false);
  const [error, setError] = useState<string | null>(null);

  // Check logged user on app start
  useEffect(() => {
    const checkUser = async () => {
      try {
        setLoading(true);
        const accessToken = await AsyncStorage.getItem('accessToken');

        if (!accessToken) {
          setIsAuthenticated(false);
          setUser(null);
          return;
        }
        const decoded: any = await jwtDecode(accessToken);

        if (decoded?.must_change_password) {
          router.replace('/auth/ChangePassword');
        }

        const userRes = await CurrentUser();

        setUser(userRes.data.user);
        setIsAuthenticated(true);
      } catch (err: any) {
        setIsAuthenticated(false);
        setUser(null);
      } finally {
        setLoading(false);
      }
    };

    checkUser();
  }, []);

  // LOGIN
  const login = async (username: string, password: string) => {
    try {
      setLoading(true);
      setError(null);

      const response = await UserLogin(username, password);

      if (response?.data?.success) {
        const { accessToken, refreshToken } = response.data;

        if (accessToken) {
          await AsyncStorage.setItem('accessToken', accessToken);
        }

        if (refreshToken) {
          await AsyncStorage.setItem('refreshToken', refreshToken);
        }

        const userRes = await CurrentUser();
        setUser(userRes.data.user);
        setIsAuthenticated(true);
      }
    } catch (err: any) {
      setError(err?.response?.data?.message || 'Login failed');
      setIsAuthenticated(false);
    } finally {
      setLoading(false);
    }
  };

  // LOGOUT
  const logout = async () => {
    try {
      setLoading(true);

      await UserLogout();

      await AsyncStorage.removeItem('accessToken');
      await AsyncStorage.removeItem('refreshToken');

      setUser(null);
      setIsAuthenticated(false);
    } catch (err) {
      console.log(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        loading,
        login,
        logout,
        isAuthenticated,
        error,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

const useAuth = () => {
  const context = useContext(AuthContext);

  if (!context) {
    throw new Error('useAuth must be used inside AuthProvider');
  }

  return context;
};

export default useAuth;
