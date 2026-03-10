import axios from 'axios';
import AsyncStorage from '@react-native-async-storage/async-storage';

import { Platform } from 'react-native';
import { ipAddress } from '@/utils/IpAddress';

const api = axios.create({
  baseURL: `http://${ipAddress}:4500/api/v1`,
  withCredentials: true,
  headers: {
    deviceType: Platform.OS,
  },
});

api.interceptors.request.use(
  async (config) => {
    const token = await AsyncStorage.getItem('accessToken');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

api.interceptors.response.use(
  (response) => response,
  async (error: any) => {
    const originalRequest = error.config;
    if (error.response.status === 401 && !originalRequest._retry) {
      const refreshToken = await AsyncStorage.getItem('refreshToken');
      if (refreshToken) {
        const response = await api.post(
          '/auth/user/refresh-token',
          { refreshToken },
          {
            withCredentials: true,
          }
        );
        if (response.status === 200) {
          await AsyncStorage.setItem('accessToken', response.data.accessToken);
          await AsyncStorage.setItem(
            'refreshToken',
            response.data.refreshToken
          );
          originalRequest.headers.Authorization = `Bearer ${response.data.accessToken}`;
          return api(originalRequest);
        }
      }
    }
    return Promise.reject(error);
  }
);

export default api;
