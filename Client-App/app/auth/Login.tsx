import {
  View,
  Text,
  KeyboardAvoidingView,
  Platform,
  TextInput,
  Pressable,
  ActivityIndicator
} from "react-native";

import React, { useEffect, useState } from "react";
import { useRouter } from "expo-router";
import Toast from "react-native-toast-message";
import useAuth from "@/context/AuthContext";

const Login = () => {

  const { login, isAuthenticated, user, error, loading } = useAuth();

  const router = useRouter();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  // Show login error
  useEffect(() => {

    if (error) {
      Toast.show({
        type: "error",
        text1: "Login Failed",
        text2: error
      });
    }

  }, [error]);

  // Redirect based on role
  useEffect(() => {

    if (isAuthenticated && user) {

      Toast.show({
        type: "success",
        text1: "Login Successful"
      });

      if (user.role === "Student" || user.role === "Faculty") {

        router.replace("/(user-tabs)/Home");

      } else if (user.role === "Technician") {

        router.replace("/(technician-tabs)/Dashboard");

      } else if (user.role === "Admin" || user.role === "MasterAdmin") {

        router.replace("/(admin-tabs)/Dashboard");

      }

    }

  }, [isAuthenticated, user]);

  const handleLogin = async () => {

    if (!email || !password) {

      Toast.show({
        type: "error",
        text1: "Error",
        text2: "All fields are required"
      });

      return;

    }

    await login(email, password);

  };

  return (

    <KeyboardAvoidingView
      behavior={Platform.OS === "ios" ? "padding" : "height"}
      style={{ flex: 1 }}
    >

      <View style={{ flex: 1, justifyContent: "center", padding: 20 }}>

        <Text
          style={{
            fontSize: 28,
            fontWeight: "bold",
            textAlign: "center",
            marginBottom: 20
          }}
        >
          Login
        </Text>

        <TextInput
          placeholder="Email"
          value={email}
          onChangeText={setEmail}
          style={{
            borderWidth: 1,
            borderColor: "#ccc",
            padding: 12,
            borderRadius: 8,
            marginBottom: 10
          }}
        />

        <TextInput
          placeholder="Password"
          value={password}
          onChangeText={setPassword}
          secureTextEntry
          style={{
            borderWidth: 1,
            borderColor: "#ccc",
            padding: 12,
            borderRadius: 8,
            marginBottom: 20
          }}
        />

        <Pressable
          onPress={handleLogin}
          style={{
            backgroundColor: "black",
            padding: 14,
            borderRadius: 8,
            alignItems: "center"
          }}
        >

          {loading
            ? <ActivityIndicator color="white" />
            : <Text style={{ color: "white" }}>Sign In</Text>
          }

        </Pressable>

        <View
          style={{
            flexDirection: "row",
            justifyContent: "center",
            marginTop: 25
          }}
        >
          <Text style={{ color: "#64748b" }}>
            Don't have an account?
          </Text>

          <Pressable onPress={() => router.push("/auth/RoleSelection")}>
            <Text
              style={{
                color: "#0284c7",
                fontWeight: "bold"
              }}
            >
              {" "}Register
            </Text>
          </Pressable>

        </View>

      </View>

    </KeyboardAvoidingView>

  );

};

export default Login;
