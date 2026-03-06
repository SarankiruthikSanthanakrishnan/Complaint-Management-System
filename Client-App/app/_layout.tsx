import { AuthProvider } from "@/context/AuthContext";
import { Stack } from "expo-router";
import { StatusBar } from "react-native";

import Toast from "react-native-toast-message";

export default function RootLayout() {

  return(
    <>
      <AuthProvider>
        <StatusBar barStyle="dark-content" />
        <Stack screenOptions={{ headerShown:false }} />
      </AuthProvider>

      <Toast />
    </>
  )

}
