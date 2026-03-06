import axios from "axios"
import AsyncStorage from "@react-native-async-storage/async-storage";

const api = axios.create({
    baseURL:'http://10.28.207.123:4500/api/v1',
    withCredentials:true
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
