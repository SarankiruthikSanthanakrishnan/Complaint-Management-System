import { View, Text, KeyboardAvoidingView, Platform, TextInput, Pressable, ActivityIndicator } from 'react-native'
import React, { useState } from 'react'
import { useLocalSearchParams, useRouter } from 'expo-router'
import Toast from "react-native-toast-message"
import { UserRegister } from '@/services/AuthService'


const Register = () => {
  const router = useRouter()
  // Retrieve the regNo passed from VerifyRegno.tsx
  const { regNo } = useLocalSearchParams()

  const [password, setPassword] = useState("")
  const [confirmPassword, setConfirmPassword] = useState("")
  const [loading, setLoading] = useState(false)

  const handleRegister = async () => {
    if (!password.trim() || !confirmPassword.trim()) {
      Toast.show({
        type: "error",
        text1: "Error",
        text2: "Both password fields are required"
      })
      return
    }

    if (password !== confirmPassword) {
      Toast.show({
        type: "error",
        text1: "Error",
        text2: "Passwords do not match"
      })
      return
    }

    try {
      setLoading(true)

      const payload = {
        reg_no: regNo ,
        password: password,
        confirmpassword: confirmPassword
      }

      const response = await UserRegister(payload);

      if (response?.data?.success || response?.status === 200 || response?.status === 201) {
        Toast.show({
          type: "success",
          text1: "Registration Successful",
          text2: "You can now login with your new credentials."
        })

        // Redirect back to login page
        router.replace('/auth/Login')
      }

    } catch (err:any) {
      Toast.show({
        type: "error",
        text1: "Registration Failed",
        text2: err?.response?.data?.message || "An error occurred during registration"
      })
    } finally {
      setLoading(false)
    }
  }

  return (
    <KeyboardAvoidingView
      behavior={Platform.OS === "ios" ? "padding" : "height"}
      style={{flex:1}}
    >
      <View style={{flex:1, justifyContent:'center', padding:20, backgroundColor: '#f8fafc'}}>
        <Text style={{fontSize:28,fontWeight:"bold",textAlign:'center',marginBottom:10, color: '#0f172a'}}>
          Complete Registration
        </Text>
        <Text style={{fontSize:16,textAlign:'center',marginBottom:30, color: '#64748b'}}>
          Set a password for your account (Reg No: {regNo})
        </Text>

        <TextInput
          placeholder="Password"
          value={password}
          onChangeText={setPassword}
          secureTextEntry
          style={{
            borderWidth:1,
            borderColor:"#ccc",
            backgroundColor: "white",
            padding:14,
            borderRadius:8,
            marginBottom:15,
            fontSize: 16
          }}
        />

        <TextInput
          placeholder="Confirm Password"
          value={confirmPassword}
          onChangeText={setConfirmPassword}
          secureTextEntry
          style={{
            borderWidth:1,
            borderColor:"#ccc",
            backgroundColor: "white",
            padding:14,
            borderRadius:8,
            marginBottom:25,
            fontSize: 16
          }}
        />

        <Pressable
          onPress={handleRegister}
          disabled={loading}
          style={{
            backgroundColor:'#0284c7',
            padding:16,
            borderRadius:8,
            alignItems:'center'
          }}
        >
          {loading
            ? <ActivityIndicator color="white"/>
            : <Text style={{color:"white", fontSize: 16, fontWeight: 'bold'}}>Register</Text>
          }
        </Pressable>

        <Pressable
          onPress={() => router.back()}
          style={{
            padding:16,
            marginTop: 10,
            alignItems:'center'
          }}
        >
          <Text style={{color:"#64748b", fontSize: 16}}>Go Back</Text>
        </Pressable>
      </View>
    </KeyboardAvoidingView>
  )
}

export default Register
