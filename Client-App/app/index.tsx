import { Redirect } from "expo-router";
import { useAuth } from "./context/AuthContext";
import { ActivityIndicator, View } from "react-native";

export default function Index() {

  const { user, loading } = useAuth();

  if (loading) {
    return (
      <View style={{flex:1,justifyContent:"center"}}>
        <ActivityIndicator />
      </View>
    );
  }

  if (!user) {
    return <Redirect href="/auth/Login" />;
  }

  return <Redirect href="/(tabs)/Home" />;
}
