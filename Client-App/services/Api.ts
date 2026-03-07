import axios from "axios"
import AsyncStorage from "@react-native-async-storage/async-storage";

import Constants from "expo-constants";

// Extract IP from Expo development server
const debuggerHost = Constants.expoConfig?.hostUri;
const ipAddress = debuggerHost?.split(':')[0];

const api = axios.create({
    baseURL: `http://${ipAddress}:4500/api/v1`,
    withCredentials:true,
})

api.interceptors.request.use(
  async (config) => {
    const token = await AsyncStorage.getItem("accessToken");
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

export default api;
