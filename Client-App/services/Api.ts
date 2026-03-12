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
      originalRequest._retry = true;
      const refreshToken = await AsyncStorage.getItem('refreshToken');
      if (refreshToken) {
        try {
          const response = await api.post(
            '/auth/user/refresh-token',
            { refreshToken },
            {
              withCredentials: true,
            }
          );
          if (response.status === 200) {
            await AsyncStorage.setItem(
              'accessToken',
              response.data.accessToken
            );
            // Updating the original request with the new access token
            originalRequest.headers.Authorization = `Bearer ${response.data.accessToken}`;
            return api(originalRequest);
          }
        } catch (refreshError) {
          // If refresh token is also invalid or expired, log them out
          await AsyncStorage.removeItem('accessToken');
          await AsyncStorage.removeItem('refreshToken');
          // You can also add router push here if needed, but often clearing storage
          // triggers the AuthContext to re-render and kick the user out.
        }
      } else {
        // No refresh token available, log out
        await AsyncStorage.removeItem('accessToken');
      }
    }
    return Promise.reject(error);
  }
);

export default api;
