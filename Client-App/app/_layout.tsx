import { Stack } from "expo-router";
import { StatusBar } from "react-native";
import { AuthProvider } from "./context/AuthContext";


export default function RootLayout() {

  return(
    <>
    <AuthProvider>
    <StatusBar barStyle="dark-content"/>
    <Stack screenOptions={{headerShown:false}} />
    </AuthProvider>

    </>

  )
}
