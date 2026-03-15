import AsyncStorage from '@react-native-async-storage/async-storage';
import api from './Api';
import axios from 'axios';
import { ipAddress } from '@/utils/IpAddress';

export const UserVerify = (data: string) => {
  return api.post('/auth/user/verify-regno', { reg_no: data });
};

export const UserRegister = (userData: Object) => {
  return api.post('/auth/user/register', userData);
};

export const UserLogin = (username: string, password: string) => {
  return api.post('/auth/user/login', { username, password });
};

export const CurrentUser = () => {
  return api.get('/auth/user/get-user');
};

export const UserLogout = () => {
  return api.post('/auth/user/logout');
};

export const UpdateUser = (userData: Object) => {
  return api.put('/auth/user/updateProfile', userData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
  });
};

export const ChangeUserPassword = (
  password: string,
  confirmPassword: string
) => {
  return api.post('/auth/user/change-password', { password, confirmPassword });
};

export const ForgotPassword = (email: string) => {
  return api.post('/auth/user/forgot-password', { email });
};

export const ResetPassword = (
  token: string,
  password: string,
  confirmpassword: string
) => {
  return api.post(`/auth/user/reset-password?token=${token}`, {
    password: password,
    confirmpassword: confirmpassword,
  });
};

export const refreshResponse = (refreshToken: string) => {
  return axios.post(
    `http://${ipAddress}:4500/api/v1/auth/user/refresh-token`,
    {},
    {
      headers: {
        Authorization: `Bearer ${refreshToken}`,
      },
    }
  );
};
