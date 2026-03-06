import useAuth from "@/context/AuthContext";
import { Redirect } from "expo-router";
import { useEffect, useState } from "react";
import AsyncStorage from "@react-native-async-storage/async-storage";

import { ActivityIndicator, View } from "react-native";

export default function Index() {

  const { user, loading } = useAuth();
  const [hasSeenRoleSelection, setHasSeenRoleSelection] = useState<boolean | null>(null);

  useEffect(() => {
    const checkRoleSelection = async () => {
      try {
        const value = await AsyncStorage.getItem("hasSeenRoleSelection");
        setHasSeenRoleSelection(value === "true");
      } catch (e) {
        setHasSeenRoleSelection(false);
      }
    };
    checkRoleSelection();
  }, []);

  if (loading || hasSeenRoleSelection === null) {
    return (
      <View style={{flex:1,justifyContent:"center"}}>
        <ActivityIndicator size="large" />
      </View>
    );
  }

  if (!user) {
    if (!hasSeenRoleSelection) {
      return <Redirect href="/auth/RoleSelection" />;
    }
    return <Redirect href="/auth/Login" />;
  }

  if (user.role === "Student" || user.role === "Faculty") {
    return <Redirect href="/(user-tabs)/Home" />;
  } else if (user.role === "Technician") {
    return <Redirect href="/(technician-tabs)/Dashboard" />;
  } else if (user.role === "Admin" || user.role === "MasterAdmin") {
    return <Redirect href="/(admin-tabs)/Dashboard" />;
  }

  return <Redirect href="/(user-tabs)/Home" />;
}
