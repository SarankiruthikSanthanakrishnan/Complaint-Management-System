import axios from 'axios';
import AsyncStorage from '@react-native-async-storage/async-storage';

import { Platform } from 'react-native';
import { ipAddress } from '@/utils/IpAddress';
import { refreshResponse } from './AuthService';

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

    console.log('Interceptor status:', error.response?.status);

    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;

      const refreshToken = await AsyncStorage.getItem('refreshToken');

      if (refreshToken) {
        try {
          console.log('Attempting to refresh token...');

          const response = await refreshResponse(refreshToken);

          const newAccessToken = response.data.accessToken;

          await AsyncStorage.setItem('accessToken', newAccessToken);

          originalRequest.headers = originalRequest.headers || {};
          originalRequest.headers.Authorization = `Bearer ${newAccessToken}`;

          return api(originalRequest);
        } catch (refreshError) {
          await AsyncStorage.removeItem('accessToken');
          await AsyncStorage.removeItem('refreshToken');
        }
      } else {
        await AsyncStorage.removeItem('accessToken');
      }
    }

    return Promise.reject(error);
  }
);

export default api;
